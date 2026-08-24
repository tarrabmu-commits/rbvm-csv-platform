package io.rbvm.csv;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Executes one CSV-first enrichment from the V30 local public-intelligence store only.
 *
 * <p>The database lookup runs in-process through the explicit exporter boundary. Python receives
 * only generated local files and a deliberately restricted environment, so database credentials,
 * provider API keys, and tenant state are never inherited by enrichment subprocesses.</p>
 */
final class CsvFirstLocalEnrichmentExecutor {
    static final String ACQUISITION_MODE = "LOCAL_V30_STORE";
    private static final Duration PROCESS_TIMEOUT = Duration.ofMinutes(10);
    private static final int MAX_PROCESS_OUTPUT_BYTES = 64 * 1024;
    private static final Set<String> PROCESS_ENV_ALLOWLIST = Set.of(
            "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT"
    );

    @FunctionalInterface
    interface StageSink {
        void update(String stage) throws IOException;
    }

    record Result(boolean success, String failureCode, String detail, boolean timedOut, boolean interrupted) {
        static Result success() {
            return new Result(true, null, null, false, false);
        }

        static Result failed(String failureCode, String detail) {
            return new Result(false, failureCode, detail, false, false);
        }

        static Result timedOut(String detail) {
            return new Result(false, "TIMEOUT", detail, true, false);
        }

        static Result interrupted(String detail) {
            return new Result(false, "INTERRUPTED", detail, false, true);
        }
    }

    private final Path dataDirectory;
    private final Path repositoryRoot;
    private final Path enrichmentScript;
    private final Path snapshotBuilderScript;
    private final String python;
    private final CsvFirstLocalIntelligenceSnapshotExporter exporter;

    CsvFirstLocalEnrichmentExecutor(
            Path dataDirectory,
            CsvFirstLocalIntelligenceSnapshotExporter exporter
    ) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        this.exporter = Objects.requireNonNull(exporter, "exporter");
        String configuredRoot = System.getenv().getOrDefault("RBVM_REPOSITORY_ROOT", ".");
        this.repositoryRoot = Path.of(configuredRoot).toAbsolutePath().normalize();
        this.enrichmentScript = repositoryRoot.resolve("scripts/enrich-uploaded-csv.py").normalize();
        this.snapshotBuilderScript = repositoryRoot
                .resolve("scripts/build-local-public-intelligence-snapshot.py").normalize();
        this.python = System.getenv().getOrDefault("RBVM_PYTHON", "python3");
    }

    boolean available() {
        return regularScript(enrichmentScript) && regularScript(snapshotBuilderScript);
    }

    Result execute(UUID runId, StageSink stages) {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(stages, "stages");
        try {
            Path run = runDirectory(runId);
            Path input = run.resolve("input.csv");
            Path output = run.resolve("enriched.csv");
            Path snapshot = run.resolve("public-intel.json");
            Path report = run.resolve("report.json");
            Path collectorReport = run.resolve("collector-report.json");
            Path exportDirectory = run.resolve("local-public-intelligence");
            Path snapshotLog = run.resolve("local-snapshot-process.log");
            Path enrichmentLog = run.resolve("process.log");
            if (!Files.isRegularFile(input) || Files.isSymbolicLink(input)) {
                return Result.failed("INVALID_INPUT", "staged CSV-first input is unavailable");
            }
            if (!available()) {
                return Result.failed(
                        "CSV_FIRST_LOCAL_INTELLIGENCE_UNAVAILABLE",
                        "local CSV-first enrichment scripts are unavailable; configure RBVM_REPOSITORY_ROOT"
                );
            }

            String observedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
            stages.update("READING_LOCAL_PUBLIC_INTELLIGENCE");
            try {
                exporter.export(input, exportDirectory);
            } catch (IOException | RuntimeException exception) {
                return Result.failed(
                        "LOCAL_INTELLIGENCE_LOOKUP_FAILED",
                        diagnostic(exception, "local public-intelligence lookup failed")
                );
            }

            stages.update("BUILDING_LOCAL_PUBLIC_INTELLIGENCE_SNAPSHOT");
            ProcessOutcome snapshotOutcome = runProcess(
                    new ProcessBuilder(
                            python,
                            snapshotBuilderScript.toString(),
                            exportDirectory.toString(),
                            snapshot.toString(),
                            "--report", collectorReport.toString(),
                            "--observed-at", observedAt
                    ),
                    snapshotLog
            );
            if (snapshotOutcome.interrupted()) {
                return Result.interrupted("local public-intelligence snapshot build was interrupted");
            }
            if (snapshotOutcome.timedOut()) {
                return Result.timedOut("local public-intelligence snapshot build exceeded the execution limit");
            }
            if (!snapshotOutcome.success() || !Files.isRegularFile(snapshot)) {
                return Result.failed(
                        "LOCAL_INTELLIGENCE_SNAPSHOT_FAILED",
                        fileDiagnostic(snapshotLog, "local public-intelligence snapshot build failed")
                );
            }

            stages.update("ENRICHING_CSV_FROM_LOCAL_PUBLIC_INTELLIGENCE");
            ProcessOutcome enrichmentOutcome = runProcess(
                    new ProcessBuilder(
                            python,
                            enrichmentScript.toString(),
                            input.toString(),
                            output.toString(),
                            "--intel-snapshot", snapshot.toString(),
                            "--report", report.toString()
                    ),
                    enrichmentLog
            );
            if (enrichmentOutcome.interrupted()) {
                return Result.interrupted("CSV-first local enrichment was interrupted");
            }
            if (enrichmentOutcome.timedOut()) {
                return Result.timedOut("CSV-first local enrichment exceeded the execution limit");
            }
            if (!enrichmentOutcome.success()
                    || !Files.isRegularFile(output)
                    || !Files.isRegularFile(report)) {
                return Result.failed(
                        "ENRICHMENT_FAILED",
                        fileDiagnostic(enrichmentLog, "CSV-first local enrichment failed")
                );
            }

            Files.deleteIfExists(snapshotLog);
            Files.deleteIfExists(enrichmentLog);
            return Result.success();
        } catch (IOException exception) {
            return Result.failed("LOCAL_ENRICHMENT_IO_FAILED", diagnostic(exception, "local enrichment I/O failed"));
        }
    }

    private ProcessOutcome runProcess(ProcessBuilder builder, Path processLog) throws IOException {
        builder.directory(repositoryRoot.toFile());
        restrictEnvironment(builder.environment(), System.getenv());
        builder.redirectErrorStream(true);
        builder.redirectOutput(processLog.toFile());
        Process process = builder.start();
        boolean finished;
        try {
            finished = process.waitFor(PROCESS_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return new ProcessOutcome(false, false, true);
        }
        if (!finished) {
            process.destroyForcibly();
            return new ProcessOutcome(false, true, false);
        }
        return new ProcessOutcome(process.exitValue() == 0, false, false);
    }

    static void restrictEnvironment(Map<String, String> target, Map<String, String> inherited) {
        target.clear();
        for (String key : PROCESS_ENV_ALLOWLIST) {
            String value = inherited.get(key);
            if (value != null && !value.isBlank()) target.put(key, value);
        }
        target.put("PYTHONIOENCODING", "utf-8");
        target.put("PYTHONUTF8", "1");
        target.put("PYTHONUNBUFFERED", "1");
    }

    private Path runDirectory(UUID runId) throws IOException {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        if (!run.startsWith(runs)) throw new IOException("invalid run directory");
        return run;
    }

    private static boolean regularScript(Path path) {
        return Files.isRegularFile(path) && !Files.isSymbolicLink(path);
    }

    private static String fileDiagnostic(Path path, String fallback) throws IOException {
        if (!Files.isRegularFile(path) || Files.isSymbolicLink(path)) return fallback;
        byte[] bytes = Files.readAllBytes(path);
        String value = new String(
                bytes, 0, Math.min(bytes.length, MAX_PROCESS_OUTPUT_BYTES), StandardCharsets.UTF_8).trim();
        return value.isBlank() ? fallback : value;
    }

    private static String diagnostic(Exception exception, String fallback) {
        String message = exception.getMessage();
        if (message == null || message.isBlank()) return fallback;
        return message.length() <= MAX_PROCESS_OUTPUT_BYTES
                ? message : message.substring(0, MAX_PROCESS_OUTPUT_BYTES);
    }

    private record ProcessOutcome(boolean success, boolean timedOut, boolean interrupted) {
    }
}
