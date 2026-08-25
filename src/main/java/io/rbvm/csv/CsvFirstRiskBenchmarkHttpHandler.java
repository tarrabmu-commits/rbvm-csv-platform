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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Materializes deterministic descriptive comparisons of the four active CSV-first risk methods. */
public final class CsvFirstRiskBenchmarkHttpHandler implements HttpHandler {
    public static final String ROOT = "/api/v1/csv-first-risk-benchmarks";
    public static final String CONTRACT_ID = "CSV_FIRST_RISK_BENCHMARK_HTTP_V1";

    private static final Duration PROCESS_TIMEOUT = Duration.ofMinutes(10);
    private static final int MAX_DIAGNOSTIC_BYTES = 64 * 1024;
    private static final Set<String> PROCESS_ENV_ALLOWLIST = Set.of(
            "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT");
    private static final Pattern MATERIALIZE_PATH = Pattern.compile(
            "^" + ROOT + "/([0-9a-fA-F-]{36})/([0-9a-fA-F-]{36})$");
    private static final Pattern REPORT_PATH = Pattern.compile(
            "^" + ROOT + "/([0-9a-fA-F-]{36})/([0-9a-fA-F-]{36})/([0-9a-f]{64})/report$");
    private static final List<String> ACTIVE_FIXTURES = List.of(
            "BRINQA_STYLE_CSV_V1.json",
            "JUPITERONE_STYLE_CSV_V2.json",
            "RBVM_CSV_BOUNDED_RISK_V3.json",
            "SERVICENOW_STYLE_CSV_V1.json"
    );

    private final Path dataDirectory;
    private final ApiKeyAuthenticator authenticator;
    private final Path repositoryRoot;
    private final Path benchmarkScript;
    private final Path evaluatorScript;
    private final Path activeMethodsDirectory;
    private final String python;

    public CsvFirstRiskBenchmarkHttpHandler(Path dataDirectory, ApiKeyAuthenticator authenticator) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory").toAbsolutePath().normalize();
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        this.repositoryRoot = Path.of(System.getenv().getOrDefault("RBVM_REPOSITORY_ROOT", "."))
                .toAbsolutePath().normalize();
        this.benchmarkScript = repositoryRoot.resolve("scripts/benchmark-csv-first-risk-methods.py").normalize();
        this.evaluatorScript = repositoryRoot.resolve("scripts/evaluate-csv-first-risk.py").normalize();
        this.activeMethodsDirectory = repositoryRoot.resolve("docs/fixtures/csv-first-risk-methods-active").normalize();
        this.python = System.getenv().getOrDefault("RBVM_PYTHON", "python3");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String verb = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
            String path = exchange.getRequestURI().getPath();
            Matcher report = REPORT_PATH.matcher(path);
            if (report.matches()) {
                requireRole(exchange, ApiRole.VIEWER);
                if (!"GET".equals(verb)) {
                    methodNotAllowed(exchange, "GET");
                    return;
                }
                UUID runId = parseId(exchange, report.group(1), "INVALID_RUN_ID");
                if (runId == null) return;
                UUID analysisId = parseId(exchange, report.group(2), "INVALID_ANALYSIS_ID");
                if (analysisId == null) return;
                readReport(exchange, runId, analysisId, report.group(3));
                return;
            }
            Matcher materialize = MATERIALIZE_PATH.matcher(path);
            if (materialize.matches()) {
                requireRole(exchange, ApiRole.OPERATOR);
                if (!"POST".equals(verb)) {
                    methodNotAllowed(exchange, "POST");
                    return;
                }
                UUID runId = parseId(exchange, materialize.group(1), "INVALID_RUN_ID");
                if (runId == null) return;
                UUID analysisId = parseId(exchange, materialize.group(2), "INVALID_ANALYSIS_ID");
                if (analysisId == null) return;
                materialize(exchange, runId, analysisId);
                return;
            }
            problem(exchange, 404, "NOT_FOUND", "The requested CSV-first risk benchmark route does not exist");
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            exception.printStackTrace(System.err);
            problem(exchange, 500, "INTERNAL_ERROR", "CSV-first risk benchmark request failed");
        } finally {
            exchange.close();
        }
    }

    private void materialize(HttpExchange exchange, UUID runId, UUID analysisId) throws IOException {
        ensureRuntime();
        Path analysis = sourceAnalysis(runId, analysisId);
        if (analysis == null) {
            problem(exchange, 404, "ANALYSIS_NOT_FOUND", "Immutable CSV-first contextual analysis does not exist");
            return;
        }
        String sourceSha = sha256File(analysis);
        String executionSha = executionIdentitySha();
        Path target = benchmarkDirectory(analysis, sourceSha, executionSha);
        if (published(target)) {
            sendMetadata(exchange, 200, runId, analysisId, sourceSha, executionSha, true);
            return;
        }
        if (Files.exists(target)) {
            problem(exchange, 409, "RISK_BENCHMARK_ARTIFACT_CONFLICT",
                    "Benchmark target exists but is incomplete; manual integrity review is required");
            return;
        }

        Path analysisDirectory = analysis.getParent();
        Path staging = analysisDirectory.resolve(".risk-benchmark-stage-" + UUID.randomUUID()).normalize();
        if (!staging.startsWith(analysisDirectory)) throw new IOException("invalid benchmark staging directory");
        Files.createDirectories(staging);
        Path output = staging.resolve("risk-method-benchmark.json");
        Path log = staging.resolve("process.log");
        ProcessOutcome outcome = runProcess(new ProcessBuilder(
                python,
                benchmarkScript.toString(),
                analysis.toString(),
                activeMethodsDirectory.toString(),
                output.toString()), log);
        if (outcome.interrupted()) {
            deleteTree(staging);
            problem(exchange, 503, "CSV_FIRST_RISK_BENCHMARK_INTERRUPTED", "Risk benchmark was interrupted");
            return;
        }
        if (outcome.timedOut()) {
            deleteTree(staging);
            problem(exchange, 504, "CSV_FIRST_RISK_BENCHMARK_TIMEOUT", "Risk benchmark exceeded the execution limit");
            return;
        }
        if (!outcome.success() || !regularFile(output)) {
            String diagnostic = boundedDiagnostic(log);
            deleteTree(staging);
            problem(exchange, 422, "CSV_FIRST_RISK_BENCHMARK_FAILED",
                    diagnostic.isBlank() ? "Risk benchmark could not be derived" : diagnostic);
            return;
        }
        Files.deleteIfExists(log);
        Files.createDirectories(target.getParent());
        try {
            Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (FileAlreadyExistsException exception) {
            deleteTree(staging);
            if (!published(target)) {
                problem(exchange, 409, "RISK_BENCHMARK_ARTIFACT_CONFLICT",
                        "Concurrent benchmark publication produced an incomplete target");
                return;
            }
            sendMetadata(exchange, 200, runId, analysisId, sourceSha, executionSha, true);
            return;
        } catch (AtomicMoveNotSupportedException exception) {
            deleteTree(staging);
            problem(exchange, 503, "ATOMIC_RISK_BENCHMARK_PUBLICATION_UNAVAILABLE",
                    "Filesystem does not support atomic benchmark publication");
            return;
        }
        if (!published(target)) {
            problem(exchange, 500, "RISK_BENCHMARK_PUBLICATION_INTEGRITY_FAILURE",
                    "Published risk benchmark failed integrity checks");
            return;
        }
        sendMetadata(exchange, 201, runId, analysisId, sourceSha, executionSha, false);
    }

    private void readReport(
            HttpExchange exchange,
            UUID runId,
            UUID analysisId,
            String executionSha
    ) throws IOException {
        Path analysis = sourceAnalysis(runId, analysisId);
        if (analysis == null) {
            problem(exchange, 404, "ANALYSIS_NOT_FOUND", "Immutable CSV-first contextual analysis does not exist");
            return;
        }
        String sourceSha = sha256File(analysis);
        Path report = benchmarkDirectory(analysis, sourceSha, executionSha).resolve("risk-method-benchmark.json").normalize();
        if (!regularFile(report)) {
            problem(exchange, 404, "RISK_BENCHMARK_NOT_FOUND", "CSV-first risk benchmark artifact does not exist");
            return;
        }
        exchange.getResponseHeaders().set("Content-Disposition",
                "attachment; filename=\"rbvm-risk-benchmark-" + runId + "-" + analysisId + "-" + executionSha + ".json\"");
        sendBytes(exchange, 200, "application/json; charset=utf-8", Files.readAllBytes(report));
    }

    private void sendMetadata(
            HttpExchange exchange,
            int status,
            UUID runId,
            UUID analysisId,
            String sourceSha,
            String executionSha,
            boolean replayed
    ) throws IOException {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("contractId", CONTRACT_ID);
        response.put("runId", runId.toString());
        response.put("analysisId", analysisId.toString());
        response.put("sourceAnalysisSha256", sourceSha);
        response.put("benchmarkExecutionSha256", executionSha);
        response.put("semantics", "DESCRIPTIVE_COMPARISON_ONLY_NO_METHOD_SELECTION");
        response.put("replayed", replayed);
        response.put("benchmarkReport", ROOT + "/" + runId + "/" + analysisId + "/" + executionSha + "/report");
        sendBytes(exchange, status, "application/json; charset=utf-8",
                JsonOutput.object(response).getBytes(StandardCharsets.UTF_8));
    }

    private Path sourceAnalysis(UUID runId, UUID analysisId) throws IOException {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        if (!run.startsWith(runs)) throw new IOException("invalid run directory");
        Path analyses = run.resolve("analyses").normalize();
        Path analysisDirectory = analyses.resolve(analysisId.toString()).normalize();
        if (!analysisDirectory.startsWith(analyses)) throw new IOException("invalid analysis directory");
        Path analysis = analysisDirectory.resolve("analysis.csv").normalize();
        if (!analysis.startsWith(analysisDirectory)) throw new IOException("invalid analysis path");
        return regularFile(analysis) ? analysis : null;
    }

    private Path benchmarkDirectory(Path analysis, String sourceSha, String executionSha) throws IOException {
        Path analysisDirectory = analysis.getParent();
        Path root = analysisDirectory.resolve("risk-benchmarks").normalize();
        Path source = root.resolve(sourceSha).normalize();
        Path target = source.resolve(executionSha).normalize();
        if (!target.startsWith(root)) throw new IOException("invalid benchmark target directory");
        return target;
    }

    private String executionIdentitySha() throws IOException {
        MessageDigest digest = sha256Digest();
        updateDigest(digest, CONTRACT_ID);
        updateDigest(digest, "benchmark=" + sha256File(benchmarkScript));
        updateDigest(digest, "evaluator=" + sha256File(evaluatorScript));
        for (String name : ACTIVE_FIXTURES) {
            Path fixture = activeMethodsDirectory.resolve(name).normalize();
            if (!fixture.startsWith(activeMethodsDirectory) || !regularFile(fixture)) {
                throw new IOException("missing active risk method fixture: " + name);
            }
            updateDigest(digest, name + "=" + sha256File(fixture));
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private void ensureRuntime() throws IOException {
        if (!regularFile(benchmarkScript)) throw new IOException("CSV-first risk benchmark script is unavailable");
        if (!regularFile(evaluatorScript)) throw new IOException("CSV-first risk evaluator script is unavailable");
        if (!Files.isDirectory(activeMethodsDirectory) || Files.isSymbolicLink(activeMethodsDirectory)) {
            throw new IOException("active CSV-first risk method directory is unavailable");
        }
        List<String> actual = new ArrayList<>();
        try (var stream = Files.list(activeMethodsDirectory)) {
            stream.filter(path -> path.getFileName().toString().endsWith(".json"))
                    .filter(CsvFirstRiskBenchmarkHttpHandler::regularFile)
                    .map(path -> path.getFileName().toString())
                    .sorted()
                    .forEach(actual::add);
        }
        if (!actual.equals(ACTIVE_FIXTURES)) {
            throw new IOException("active CSV-first risk method catalog drift");
        }
    }

    private ProcessOutcome runProcess(ProcessBuilder builder, Path log) throws IOException {
        Map<String, String> inherited = new LinkedHashMap<>();
        for (String name : PROCESS_ENV_ALLOWLIST) {
            String value = System.getenv(name);
            if (value != null) inherited.put(name, value);
        }
        builder.environment().clear();
        builder.environment().putAll(inherited);
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
        if (!regularFile(log)) return "";
        byte[] bytes = Files.readAllBytes(log);
        int length = Math.min(bytes.length, MAX_DIAGNOSTIC_BYTES);
        return new String(bytes, Math.max(0, bytes.length - length), length, StandardCharsets.UTF_8).trim();
    }

    private static boolean published(Path target) {
        return Files.isDirectory(target)
                && !Files.isSymbolicLink(target)
                && regularFile(target.resolve("risk-method-benchmark.json"));
    }

    private static boolean regularFile(Path path) {
        return Files.isRegularFile(path) && !Files.isSymbolicLink(path);
    }

    private static String sha256File(Path path) throws IOException {
        if (!regularFile(path)) throw new IOException("required regular file is unavailable: " + path.getFileName());
        MessageDigest digest = sha256Digest();
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[1024 * 1024];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                if (read > 0) digest.update(buffer, 0, read);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    private static void updateDigest(MessageDigest digest, String value) {
        digest.update(value.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) '\n');
    }

    private static UUID parseId(HttpExchange exchange, String raw, String code) throws IOException {
        try {
            return UUID.fromString(raw);
        } catch (IllegalArgumentException exception) {
            problem(exchange, 400, code, "Invalid CSV-first identifier");
            return null;
        }
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        Optional<AuthPrincipal> principal = authenticator.authenticate(authorization);
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
        }
    }

    private static void methodNotAllowed(HttpExchange exchange, String allow) throws IOException {
        exchange.getResponseHeaders().set("Allow", allow);
        problem(exchange, 405, "METHOD_NOT_ALLOWED", "HTTP method is not allowed for this resource");
    }

    private static void problem(HttpExchange exchange, int status, String code, String detail) throws IOException {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("type", "about:blank");
        value.put("title", code);
        value.put("status", status);
        value.put("detail", detail);
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

    private static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root)) return;
        List<Path> paths;
        try (var stream = Files.walk(root)) {
            paths = stream.sorted((left, right) -> right.compareTo(left)).toList();
        }
        for (Path path : paths) {
            Files.deleteIfExists(path);
        }
    }

    private record ProcessOutcome(boolean success, boolean timedOut, boolean interrupted) {}
}
