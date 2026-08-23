package io.rbvm.csv;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Non-blocking CSV-first public-intelligence transport.
 *
 * POST stages one immutable run scope and returns 202 immediately. A bounded
 * daemon worker executes the same enrichment script and writes a persisted
 * status artifact into the established csv-first-enrichments run directory, so
 * the existing immutable CSV/report/snapshot and contextual-analysis routes can
 * be reused after completion. The legacy synchronous transport remains intact.
 */
public final class CsvFirstEnrichmentJobHttpHandler implements HttpHandler {
    public static final String CONTRACT_ID = "CSV_FIRST_ENRICHMENT_JOB_HTTP_V1";

    private static final String ROOT = "/api/v1/csv-first-enrichment-jobs";
    private static final Pattern STATUS_PATH = Pattern.compile(
            "^/api/v1/csv-first-enrichment-jobs/([0-9a-fA-F-]{36})$");
    private static final Duration PROCESS_TIMEOUT = Duration.ofMinutes(10);
    private static final int MAX_PROCESS_OUTPUT_BYTES = 64 * 1024;
    private static final int MAX_CONCURRENT_JOBS = 2;
    private static final int MAX_QUEUED_JOBS = 8;

    private final Path dataDirectory;
    private final Path repositoryRoot;
    private final Path enrichmentScript;
    private final Path cacheDirectory;
    private final String python;
    private final long maximumUploadBytes;
    private final ApiKeyAuthenticator authenticator;
    private final ThreadPoolExecutor workers;

    public CsvFirstEnrichmentJobHttpHandler(
            Path dataDirectory,
            long maximumUploadBytes,
            ApiKeyAuthenticator authenticator
    ) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        this.maximumUploadBytes = maximumUploadBytes;
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        String configuredRoot = System.getenv().getOrDefault("RBVM_REPOSITORY_ROOT", ".");
        this.repositoryRoot = Path.of(configuredRoot).toAbsolutePath().normalize();
        this.enrichmentScript = repositoryRoot.resolve("scripts/enrich-uploaded-csv.py").normalize();
        this.cacheDirectory = this.dataDirectory.resolve("public-cve-intel-cache").normalize();
        this.python = System.getenv().getOrDefault("RBVM_PYTHON", "python3");
        this.workers = new ThreadPoolExecutor(
                MAX_CONCURRENT_JOBS,
                MAX_CONCURRENT_JOBS,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(MAX_QUEUED_JOBS),
                runnable -> {
                    Thread thread = new Thread(runnable, "rbvm-csv-first-enrichment-job");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy()
        );
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
            String path = exchange.getRequestURI().getPath();
            if (ROOT.equals(path)) {
                requireRole(exchange, ApiRole.OPERATOR);
                if (!"POST".equals(method)) {
                    methodNotAllowed(exchange, "POST");
                    return;
                }
                create(exchange);
                return;
            }
            Matcher status = STATUS_PATH.matcher(path);
            if (status.matches()) {
                requireRole(exchange, ApiRole.VIEWER);
                if (!"GET".equals(method)) {
                    methodNotAllowed(exchange, "GET");
                    return;
                }
                UUID runId = parseRunId(exchange, status.group(1));
                if (runId != null) status(exchange, runId);
                return;
            }
            problem(exchange, 404, "NOT_FOUND", "The requested CSV-first enrichment-job route does not exist");
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            exception.printStackTrace(System.err);
            problem(exchange, 500, "INTERNAL_ERROR", "The CSV-first enrichment job request could not be completed");
        } finally {
            exchange.close();
        }
    }

    private void create(HttpExchange exchange) throws IOException {
        if (!regularScript(enrichmentScript)) {
            problem(exchange, 503, "CSV_FIRST_ENRICHMENT_UNAVAILABLE",
                    "CSV-first enrichment script is unavailable; configure RBVM_REPOSITORY_ROOT");
            return;
        }
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isCsvContentType(contentType)) {
            problem(exchange, 415, "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be text/csv, application/csv, or application/octet-stream");
            return;
        }
        if (requestTooLarge(exchange)) {
            problem(exchange, 413, "UPLOAD_TOO_LARGE", "CSV exceeds the configured upload limit");
            return;
        }

        UUID runId = UUID.randomUUID();
        Path run = runDirectory(runId);
        Files.createDirectories(run);
        Path input = run.resolve("input.csv");
        try (InputStream body = exchange.getRequestBody();
             OutputStream staged = Files.newOutputStream(input)) {
            copyBounded(body, staged, maximumUploadBytes);
        } catch (UploadTooLargeException exception) {
            deleteTree(run);
            problem(exchange, 413, "UPLOAD_TOO_LARGE", "CSV exceeds the configured upload limit");
            return;
        }

        String createdAt = Instant.now().toString();
        writeStatus(run, statusValue(runId, "QUEUED", "WAITING_FOR_WORKER", createdAt, null, null));
        try {
            workers.execute(() -> execute(runId, createdAt));
        } catch (RejectedExecutionException exception) {
            deleteTree(run);
            problem(exchange, 503, "CSV_FIRST_ENRICHMENT_JOB_CAPACITY",
                    "CSV-first enrichment capacity is temporarily full; retry after an active job completes");
            return;
        }

        Map<String, Object> response = statusValue(
                runId, "QUEUED", "WAITING_FOR_WORKER", createdAt, null, null);
        sendJson(exchange, 202, response);
    }

    private void execute(UUID runId, String createdAt) {
        try {
            Path run = runDirectory(runId);
            Path input = run.resolve("input.csv");
            Path output = run.resolve("enriched.csv");
            Path snapshot = run.resolve("public-intel.json");
            Path report = run.resolve("report.json");
            Path collectorReport = run.resolve("collector-report.json");
            Path processLog = run.resolve("process.log");

            writeStatus(run, statusValue(
                    runId, "RUNNING", "COLLECTING_PUBLIC_INTELLIGENCE", createdAt, null, null));
            ProcessBuilder builder = new ProcessBuilder(
                    python,
                    enrichmentScript.toString(),
                    input.toString(),
                    output.toString(),
                    "--snapshot-output", snapshot.toString(),
                    "--report", report.toString(),
                    "--collector-report", collectorReport.toString(),
                    "--cache-dir", cacheDirectory.toString()
            );
            ProcessOutcome outcome = runProcess(builder, processLog);
            if (outcome.interrupted()) {
                writeStatus(run, statusValue(runId, "FAILED", "INTERRUPTED", createdAt,
                        "CSV-first enrichment was interrupted", Instant.now().toString()));
                return;
            }
            if (outcome.timedOut()) {
                writeStatus(run, statusValue(runId, "FAILED", "TIMEOUT", createdAt,
                        "CSV-first enrichment exceeded the 10-minute execution limit",
                        Instant.now().toString()));
                return;
            }
            if (!outcome.success() || !Files.isRegularFile(output) || !Files.isRegularFile(report)) {
                String diagnostic = boundedDiagnostic(processLog);
                writeStatus(run, statusValue(runId, "FAILED", "ENRICHMENT_FAILED", createdAt,
                        diagnostic.isBlank() ? "CSV-first enrichment failed" : diagnostic,
                        Instant.now().toString()));
                return;
            }
            Files.deleteIfExists(processLog);
            writeStatus(run, statusValue(
                    runId, "COMPLETE", "COMPLETE", createdAt, null, Instant.now().toString()));
        } catch (Exception exception) {
            try {
                Path run = runDirectory(runId);
                writeStatus(run, statusValue(runId, "FAILED", "INTERNAL_ERROR", createdAt,
                        exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage(),
                        Instant.now().toString()));
            } catch (IOException ignored) {
                // The daemon worker has no HTTP exchange left to report through.
            }
        }
    }

    private void status(HttpExchange exchange, UUID runId) throws IOException {
        Path file = runDirectory(runId).resolve("job-status.json");
        if (!Files.isRegularFile(file) || Files.isSymbolicLink(file)) {
            problem(exchange, 404, "RUN_NOT_FOUND", "CSV-first enrichment job does not exist");
            return;
        }
        sendBytes(exchange, 200, "application/json; charset=utf-8", Files.readAllBytes(file));
    }

    private Map<String, Object> statusValue(
            UUID runId,
            String status,
            String stage,
            String createdAt,
            String detail,
            String completedAt
    ) {
        String legacyRoot = "/api/v1/csv-first-enrichments/" + runId;
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("contractId", CONTRACT_ID);
        value.put("runId", runId.toString());
        value.put("status", status);
        value.put("stage", stage);
        value.put("progressSemantics", "INDETERMINATE_PROVIDER_WORK");
        value.put("createdAt", createdAt);
        value.put("completedAt", completedAt);
        value.put("detail", detail);
        value.put("statusUrl", ROOT + "/" + runId);
        value.put("enrichedCsv", legacyRoot + "/csv");
        value.put("report", legacyRoot + "/report");
        value.put("snapshot", legacyRoot + "/snapshot");
        value.put("contextualAnalyses", legacyRoot + "/analyses");
        value.put("next", "/assets?tab=managed&setup=1&runId=" + runId);
        value.put("databaseStateUsed", false);
        value.put("scope", "INPUT_CSV_ONLY");
        return value;
    }

    private void writeStatus(Path run, Map<String, Object> value) throws IOException {
        Path status = run.resolve("job-status.json");
        Path temporary = run.resolve("job-status.json.tmp");
        Files.writeString(temporary, JsonOutput.object(value), StandardCharsets.UTF_8);
        Files.move(temporary, status, StandardCopyOption.REPLACE_EXISTING);
    }

    private Path runDirectory(UUID runId) throws IOException {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        if (!run.startsWith(runs)) throw new IOException("invalid run directory");
        return run;
    }

    private ProcessOutcome runProcess(ProcessBuilder builder, Path processLog) throws IOException {
        builder.directory(repositoryRoot.toFile());
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

    private UUID parseRunId(HttpExchange exchange, String value) throws IOException {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            problem(exchange, 400, "INVALID_RUN_ID", "Invalid CSV-first enrichment job identifier");
            return null;
        }
    }

    private static boolean regularScript(Path path) {
        return Files.isRegularFile(path) && !Files.isSymbolicLink(path);
    }

    private boolean requestTooLarge(HttpExchange exchange) {
        long length = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        return length > maximumUploadBytes;
    }

    private static String boundedDiagnostic(Path processLog) throws IOException {
        byte[] bytes = Files.isRegularFile(processLog) ? Files.readAllBytes(processLog) : new byte[0];
        return new String(bytes, 0, Math.min(bytes.length, MAX_PROCESS_OUTPUT_BYTES), StandardCharsets.UTF_8).trim();
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        Optional<AuthPrincipal> principal = authenticator.authenticate(authorization);
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
        }
    }

    private static boolean isCsvContentType(String value) {
        if (value == null) return false;
        String normalized = value.toLowerCase(Locale.ROOT).split(";", 2)[0].trim();
        return "text/csv".equals(normalized)
                || "application/csv".equals(normalized)
                || "application/octet-stream".equals(normalized);
    }

    private static long parseContentLength(String value) {
        if (value == null || value.isBlank()) return -1;
        try {
            long parsed = Long.parseLong(value);
            return parsed < 0 ? -1 : parsed;
        } catch (NumberFormatException exception) {
            return -1;
        }
    }

    private static void copyBounded(InputStream input, OutputStream output, long maximumBytes)
            throws IOException, UploadTooLargeException {
        byte[] buffer = new byte[8192];
        long total = 0;
        int read;
        while ((read = input.read(buffer)) >= 0) {
            if (read == 0) continue;
            total += read;
            if (total > maximumBytes) throw new UploadTooLargeException();
            output.write(buffer, 0, read);
        }
    }

    private static void deleteTree(Path directory) {
        if (directory == null || !Files.exists(directory)) return;
        try (var paths = Files.walk(directory)) {
            paths.sorted((left, right) -> right.getNameCount() - left.getNameCount())
                    .forEach(path -> {
                        try { Files.deleteIfExists(path); } catch (IOException ignored) { }
                    });
        } catch (IOException ignored) {
            // Best-effort cleanup for an uncommitted run.
        }
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

    private static final class UploadTooLargeException extends Exception {
        private static final long serialVersionUID = 1L;
    }
}
