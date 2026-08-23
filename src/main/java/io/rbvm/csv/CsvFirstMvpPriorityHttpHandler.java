package io.rbvm.csv;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Append-only derived treatment-priority transport for immutable CSV-first analyses.
 *
 * <p>The source analysis remains untouched. This handler executes the pinned
 * RBVM_MVP_PRIORITY_POLICY_V1 implementation against analysis.csv, atomically publishes
 * the resulting ranked CSV and report under the analysis revision, and never claims to
 * calculate Organizational Risk.</p>
 */
public final class CsvFirstMvpPriorityHttpHandler implements HttpHandler {
    public static final String CONTRACT_ID = "CSV_FIRST_MVP_PRIORITY_HTTP_V1";
    public static final String METHOD_ID = "RBVM_MVP_PRIORITY_POLICY_V1";
    public static final String METHOD_SHA256 =
            "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388";

    private static final String ROOT = "/api/v1/csv-first-priorities";
    private static final Pattern CREATE_PATH = Pattern.compile(
            "^/api/v1/csv-first-priorities/([0-9a-fA-F-]{36})/([0-9a-fA-F-]{36})$");
    private static final Pattern ARTIFACT_PATH = Pattern.compile(
            "^/api/v1/csv-first-priorities/([0-9a-fA-F-]{36})/([0-9a-fA-F-]{36})/(csv|report)$");
    private static final Duration PROCESS_TIMEOUT = Duration.ofMinutes(10);
    private static final int MAX_PROCESS_OUTPUT_BYTES = 64 * 1024;

    private final Path dataDirectory;
    private final Path repositoryRoot;
    private final Path priorityScript;
    private final String python;
    private final ApiKeyAuthenticator authenticator;

    public CsvFirstMvpPriorityHttpHandler(Path dataDirectory, ApiKeyAuthenticator authenticator) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        this.repositoryRoot = Path.of(System.getenv().getOrDefault("RBVM_REPOSITORY_ROOT", "."))
                .toAbsolutePath().normalize();
        this.priorityScript = repositoryRoot.resolve("scripts/rank-rbvm-mvp-priority.py").normalize();
        this.python = System.getenv().getOrDefault("RBVM_PYTHON", "python3");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
            String path = exchange.getRequestURI().getPath();

            Matcher create = CREATE_PATH.matcher(path);
            if (create.matches()) {
                requireRole(exchange, ApiRole.OPERATOR);
                if (!"POST".equals(method)) {
                    methodNotAllowed(exchange, "POST");
                    return;
                }
                UUID runId = parseId(exchange, create.group(1), "INVALID_RUN_ID");
                if (runId == null) return;
                UUID analysisId = parseId(exchange, create.group(2), "INVALID_ANALYSIS_ID");
                if (analysisId == null) return;
                materialize(exchange, runId, analysisId);
                return;
            }

            Matcher artifact = ARTIFACT_PATH.matcher(path);
            if (artifact.matches()) {
                requireRole(exchange, ApiRole.VIEWER);
                if (!"GET".equals(method)) {
                    methodNotAllowed(exchange, "GET");
                    return;
                }
                UUID runId = parseId(exchange, artifact.group(1), "INVALID_RUN_ID");
                if (runId == null) return;
                UUID analysisId = parseId(exchange, artifact.group(2), "INVALID_ANALYSIS_ID");
                if (analysisId == null) return;
                artifact(exchange, runId, analysisId, artifact.group(3));
                return;
            }

            problem(exchange, 404, "NOT_FOUND", "The requested CSV-first MVP-priority route does not exist");
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            exception.printStackTrace(System.err);
            problem(exchange, 500, "INTERNAL_ERROR", "CSV-first MVP priority could not be completed");
        } finally {
            exchange.close();
        }
    }

    private void materialize(HttpExchange exchange, UUID runId, UUID analysisId) throws IOException {
        if (!Files.isRegularFile(priorityScript) || Files.isSymbolicLink(priorityScript)) {
            problem(exchange, 503, "CSV_FIRST_MVP_PRIORITY_UNAVAILABLE",
                    "MVP priority script is unavailable; configure RBVM_REPOSITORY_ROOT");
            return;
        }

        Path analysisDirectory = analysisDirectory(runId, analysisId);
        Path source = analysisDirectory.resolve("analysis.csv").normalize();
        if (!source.startsWith(analysisDirectory)
                || !Files.isRegularFile(source)
                || Files.isSymbolicLink(source)) {
            problem(exchange, 404, "ANALYSIS_NOT_FOUND", "Immutable CSV-first contextual analysis does not exist");
            return;
        }

        Path target = priorityDirectory(runId, analysisId);
        if (published(target)) {
            sendCreated(exchange, runId, analysisId, true, 200);
            return;
        }
        if (Files.exists(target)) {
            problem(exchange, 409, "PRIORITY_ARTIFACT_CONFLICT",
                    "Priority target exists but is incomplete; manual integrity review is required");
            return;
        }

        Path parent = target.getParent();
        Files.createDirectories(parent);
        Path staging = analysisDirectory.resolve(".priority-stage-" + UUID.randomUUID()).normalize();
        if (!staging.startsWith(analysisDirectory)) throw new IOException("invalid priority staging directory");
        Files.createDirectories(staging);
        Path ranked = staging.resolve("priority.csv");
        Path report = staging.resolve("priority-report.json");
        Path log = staging.resolve("process.log");

        ProcessBuilder builder = new ProcessBuilder(
                python,
                priorityScript.toString(),
                source.toString(),
                ranked.toString(),
                report.toString()
        );
        ProcessOutcome outcome = runProcess(builder, log);
        if (outcome.interrupted()) {
            deleteTree(staging);
            problem(exchange, 503, "CSV_FIRST_MVP_PRIORITY_INTERRUPTED", "MVP priority derivation was interrupted");
            return;
        }
        if (outcome.timedOut()) {
            deleteTree(staging);
            problem(exchange, 504, "CSV_FIRST_MVP_PRIORITY_TIMEOUT", "MVP priority derivation exceeded the execution limit");
            return;
        }
        if (!outcome.success()
                || !Files.isRegularFile(ranked) || Files.isSymbolicLink(ranked)
                || !Files.isRegularFile(report) || Files.isSymbolicLink(report)) {
            String diagnostic = boundedDiagnostic(log);
            deleteTree(staging);
            problem(exchange, 422, "CSV_FIRST_MVP_PRIORITY_FAILED",
                    diagnostic.isBlank() ? "MVP priority could not be derived" : diagnostic);
            return;
        }
        Files.deleteIfExists(log);

        try {
            Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (FileAlreadyExistsException exception) {
            deleteTree(staging);
            if (!published(target)) {
                problem(exchange, 409, "PRIORITY_ARTIFACT_CONFLICT",
                        "Concurrent priority publication produced an incomplete target");
                return;
            }
            sendCreated(exchange, runId, analysisId, true, 200);
            return;
        } catch (AtomicMoveNotSupportedException exception) {
            deleteTree(staging);
            problem(exchange, 503, "ATOMIC_PRIORITY_PUBLICATION_UNAVAILABLE",
                    "Filesystem does not support atomic priority-artifact publication");
            return;
        }

        if (!published(target)) {
            problem(exchange, 500, "PRIORITY_PUBLICATION_INTEGRITY_FAILURE",
                    "Published priority artifacts failed integrity checks");
            return;
        }
        sendCreated(exchange, runId, analysisId, false, 201);
    }

    private void sendCreated(
            HttpExchange exchange,
            UUID runId,
            UUID analysisId,
            boolean replayed,
            int status
    ) throws IOException {
        String root = ROOT + "/" + runId + "/" + analysisId;
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("contractId", CONTRACT_ID);
        response.put("status", "COMPLETE");
        response.put("runId", runId.toString());
        response.put("analysisId", analysisId.toString());
        response.put("methodId", METHOD_ID);
        response.put("methodSha256", METHOD_SHA256);
        response.put("classification", "RBVM_POLICY");
        response.put("outputSemantics", "RELATIVE_TREATMENT_PRIORITY_PARETO_FRONT_WITHIN_INPUT_SET");
        response.put("sourceAnalysisImmutable", true);
        response.put("derivedArtifactsImmutable", true);
        response.put("replayed", replayed);
        response.put("priorityCsv", root + "/csv");
        response.put("priorityReport", root + "/report");
        response.put("organizationalRisk", "NON_COMPUTABLE");
        sendJson(exchange, status, response);
    }

    private void artifact(HttpExchange exchange, UUID runId, UUID analysisId, String type) throws IOException {
        Path target = priorityDirectory(runId, analysisId);
        Path file;
        String contentType;
        String downloadName;
        switch (type) {
            case "csv" -> {
                file = target.resolve("priority.csv");
                contentType = "text/csv; charset=utf-8";
                downloadName = "rbvm-mvp-priority-" + runId + "-" + analysisId + ".csv";
            }
            case "report" -> {
                file = target.resolve("priority-report.json");
                contentType = "application/json; charset=utf-8";
                downloadName = "rbvm-mvp-priority-report-" + runId + "-" + analysisId + ".json";
            }
            default -> throw new IllegalStateException("unexpected priority artifact type");
        }
        if (!Files.isRegularFile(file) || Files.isSymbolicLink(file)) {
            problem(exchange, 404, "PRIORITY_ARTIFACT_NOT_FOUND", "CSV-first MVP priority artifact does not exist");
            return;
        }
        exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + downloadName + "\"");
        sendBytes(exchange, 200, contentType, Files.readAllBytes(file));
    }

    private boolean published(Path target) {
        if (!Files.isDirectory(target) || Files.isSymbolicLink(target)) return false;
        Path csv = target.resolve("priority.csv");
        Path report = target.resolve("priority-report.json");
        return Files.isRegularFile(csv) && !Files.isSymbolicLink(csv)
                && Files.isRegularFile(report) && !Files.isSymbolicLink(report);
    }

    private Path analysisDirectory(UUID runId, UUID analysisId) throws IOException {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        Path analyses = run.resolve("analyses").normalize();
        Path analysis = analyses.resolve(analysisId.toString()).normalize();
        if (!run.startsWith(runs) || !analyses.startsWith(run) || !analysis.startsWith(analyses)) {
            throw new IOException("invalid analysis directory");
        }
        return analysis;
    }

    private Path priorityDirectory(UUID runId, UUID analysisId) throws IOException {
        Path analysis = analysisDirectory(runId, analysisId);
        Path root = analysis.resolve("priority").normalize();
        Path target = root.resolve(METHOD_SHA256).normalize();
        if (!root.startsWith(analysis) || !target.startsWith(root)) {
            throw new IOException("invalid priority directory");
        }
        return target;
    }

    private UUID parseId(HttpExchange exchange, String value, String code) throws IOException {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            problem(exchange, 400, code, "Invalid CSV-first identifier");
            return null;
        }
    }

    private ProcessOutcome runProcess(ProcessBuilder builder, Path log) throws IOException {
        builder.directory(repositoryRoot.toFile());
        builder.redirectErrorStream(true);
        builder.redirectOutput(log.toFile());
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

    private static String boundedDiagnostic(Path log) throws IOException {
        byte[] output = Files.isRegularFile(log) ? Files.readAllBytes(log) : new byte[0];
        return new String(
                output,
                0,
                Math.min(output.length, MAX_PROCESS_OUTPUT_BYTES),
                StandardCharsets.UTF_8
        ).trim();
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        Optional<AuthPrincipal> principal = authenticator.authenticate(
                exchange.getRequestHeaders().getFirst("Authorization"));
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
        }
    }

    private static void deleteTree(Path directory) {
        if (directory == null || !Files.exists(directory)) return;
        try (var paths = Files.walk(directory)) {
            paths.sorted((left, right) -> right.getNameCount() - left.getNameCount())
                    .forEach(path -> {
                        try { Files.deleteIfExists(path); } catch (IOException ignored) { }
                    });
        } catch (IOException ignored) { }
    }

    private static void methodNotAllowed(HttpExchange exchange, String allowed) throws IOException {
        exchange.getResponseHeaders().set("Allow", allowed);
        problem(exchange, 405, "METHOD_NOT_ALLOWED", "HTTP method is not allowed for this resource");
    }

    private static void problem(HttpExchange exchange, int status, String code, String detail) throws IOException {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("type", "about:blank");
        value.put("title", code);
        value.put("status", status);
        value.put("detail", detail);
        sendJson(exchange, status, value);
    }

    private static void sendJson(HttpExchange exchange, int status, Map<String, ?> value) throws IOException {
        sendBytes(exchange, status, "application/json; charset=utf-8",
                JsonOutput.object(value).getBytes(StandardCharsets.UTF_8));
    }

    private static void sendBytes(HttpExchange exchange, int status, String contentType, byte[] bytes)
            throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType);
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private record ProcessOutcome(boolean success, boolean timedOut, boolean interrupted) { }
}
