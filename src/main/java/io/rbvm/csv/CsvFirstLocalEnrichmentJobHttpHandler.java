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

/**
 * Product async CSV enrichment transport backed exclusively by V30 local public intelligence.
 * Non-POST/status behavior delegates to the established V1 handler so response compatibility is
 * retained while product uploads no longer invoke provider Internet collectors.
 */
public final class CsvFirstLocalEnrichmentJobHttpHandler implements HttpHandler {
    public static final String CONTRACT_ID = "CSV_FIRST_LOCAL_ENRICHMENT_JOB_HTTP_V1";
    private static final String ROOT = "/api/v1/csv-first-enrichment-jobs";
    private static final int MAX_CONCURRENT_JOBS = 1;
    private static final int MAX_QUEUED_JOBS = 8;

    private final Path dataDirectory;
    private final long maximumUploadBytes;
    private final ApiKeyAuthenticator authenticator;
    private final CsvFirstEnrichmentJobHttpHandler delegate;
    private final Optional<CsvFirstLocalEnrichmentExecutor> executor;
    private final ThreadPoolExecutor workers;

    public CsvFirstLocalEnrichmentJobHttpHandler(
            Path dataDirectory,
            long maximumUploadBytes,
            Optional<CsvFirstLocalIntelligenceSnapshotExporter> exporter,
            ApiKeyAuthenticator authenticator
    ) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        this.maximumUploadBytes = maximumUploadBytes;
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        this.delegate = new CsvFirstEnrichmentJobHttpHandler(
                dataDirectory, maximumUploadBytes, authenticator);
        this.executor = Objects.requireNonNull(exporter, "exporter")
                .map(value -> new CsvFirstLocalEnrichmentExecutor(this.dataDirectory, value));
        this.workers = new ThreadPoolExecutor(
                MAX_CONCURRENT_JOBS,
                MAX_CONCURRENT_JOBS,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(MAX_QUEUED_JOBS),
                runnable -> {
                    Thread thread = new Thread(runnable, "rbvm-csv-first-local-enrichment-job");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy()
        );
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
        String path = exchange.getRequestURI().getPath();
        if (!ROOT.equals(path) || !"POST".equals(method)) {
            delegate.handle(exchange);
            return;
        }
        try {
            requireRole(exchange, ApiRole.OPERATOR);
            create(exchange);
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            exception.printStackTrace(System.err);
            problem(exchange, 500, "INTERNAL_ERROR", "The local CSV-first enrichment job could not be created");
        } finally {
            exchange.close();
        }
    }

    private void create(HttpExchange exchange) throws IOException {
        if (executor.isEmpty() || !executor.get().available()) {
            problem(exchange, 503, "CSV_FIRST_LOCAL_INTELLIGENCE_UNAVAILABLE",
                    "CSV-first enrichment requires the PostgreSQL V30/V31 local public-intelligence runtime");
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
        writeStatus(run, statusValue(runId, "QUEUED", "WAITING_FOR_LOCAL_WORKER", createdAt, null, null));
        try {
            workers.execute(() -> execute(runId, createdAt));
        } catch (RejectedExecutionException exception) {
            deleteTree(run);
            problem(exchange, 503, "CSV_FIRST_ENRICHMENT_JOB_CAPACITY",
                    "CSV-first enrichment capacity is temporarily full; retry after an active job completes");
            return;
        }
        sendJson(exchange, 202, statusValue(
                runId, "QUEUED", "WAITING_FOR_LOCAL_WORKER", createdAt, null, null));
    }

    private void execute(UUID runId, String createdAt) {
        try {
            Path run = runDirectory(runId);
            CsvFirstLocalEnrichmentExecutor.Result result = executor.orElseThrow().execute(
                    runId,
                    stage -> writeStatus(run, statusValue(
                            runId, "RUNNING", stage, createdAt, null, null))
            );
            if (!result.success()) {
                writeStatus(run, statusValue(
                        runId,
                        "FAILED",
                        result.failureCode(),
                        createdAt,
                        result.detail(),
                        Instant.now().toString()
                ));
                return;
            }
            writeStatus(run, statusValue(
                    runId, "COMPLETE", "COMPLETE", createdAt, null, Instant.now().toString()));
        } catch (Exception exception) {
            try {
                Path run = runDirectory(runId);
                writeStatus(run, statusValue(
                        runId,
                        "FAILED",
                        "INTERNAL_ERROR",
                        createdAt,
                        exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage(),
                        Instant.now().toString()
                ));
            } catch (IOException ignored) {
                // The worker has no HTTP exchange left to report through.
            }
        }
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
        value.put("progressSemantics", "INDETERMINATE_LOCAL_WORK");
        value.put("createdAt", createdAt);
        value.put("completedAt", completedAt);
        value.put("detail", detail);
        value.put("statusUrl", ROOT + "/" + runId);
        value.put("enrichedCsv", legacyRoot + "/csv");
        value.put("report", legacyRoot + "/report");
        value.put("snapshot", legacyRoot + "/snapshot");
        value.put("contextualAnalyses", legacyRoot + "/analyses");
        value.put("next", "/assets?tab=managed&setup=1&runId=" + runId);
        value.put("acquisitionMode", CsvFirstLocalEnrichmentExecutor.ACQUISITION_MODE);
        value.put("databaseStateUsed", true);
        value.put("databaseStateScope", "GLOBAL_PUBLIC_INTELLIGENCE_ONLY");
        value.put("tenantDatabaseStateUsed", false);
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

    private void requireRole(HttpExchange exchange, ApiRole role) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        Optional<AuthPrincipal> principal = authenticator.authenticate(authorization);
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
        }
    }

    private boolean requestTooLarge(HttpExchange exchange) {
        long length = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        return length > maximumUploadBytes;
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

    private static final class UploadTooLargeException extends IOException {
        private static final long serialVersionUID = 1L;
    }
}
