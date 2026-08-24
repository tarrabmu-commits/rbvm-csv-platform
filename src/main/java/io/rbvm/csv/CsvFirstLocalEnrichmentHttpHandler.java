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
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Product synchronous CSV enrichment transport backed exclusively by V30 local public intelligence.
 * Existing artifact and contextual-analysis routes are delegated to the established V1 handler.
 */
public final class CsvFirstLocalEnrichmentHttpHandler implements HttpHandler {
    private static final String ROOT = "/api/v1/csv-first-enrichments";

    private final Path dataDirectory;
    private final long maximumUploadBytes;
    private final ApiKeyAuthenticator authenticator;
    private final CsvFirstEnrichmentHttpHandler delegate;
    private final Optional<CsvFirstLocalEnrichmentExecutor> executor;

    public CsvFirstLocalEnrichmentHttpHandler(
            Path dataDirectory,
            long maximumUploadBytes,
            Optional<CsvFirstLocalIntelligenceSnapshotExporter> exporter,
            ApiKeyAuthenticator authenticator
    ) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        this.maximumUploadBytes = maximumUploadBytes;
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        this.delegate = new CsvFirstEnrichmentHttpHandler(
                dataDirectory, maximumUploadBytes, authenticator);
        this.executor = Objects.requireNonNull(exporter, "exporter")
                .map(value -> new CsvFirstLocalEnrichmentExecutor(this.dataDirectory, value));
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
            problem(exchange, 500, "INTERNAL_ERROR", "The local CSV-first enrichment request could not be completed");
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

        CsvFirstLocalEnrichmentExecutor.Result result = executor.orElseThrow().execute(runId, ignored -> { });
        if (!result.success()) {
            int status = result.timedOut() ? 504
                    : "LOCAL_INTELLIGENCE_LOOKUP_FAILED".equals(result.failureCode()) ? 503 : 422;
            String code = result.failureCode() == null ? "CSV_FIRST_ENRICHMENT_FAILED" : result.failureCode();
            String detail = result.detail() == null ? "CSV-first local enrichment failed" : result.detail();
            deleteTree(run);
            problem(exchange, status, code, detail);
            return;
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("contractId", CsvFirstEnrichmentHttpHandler.CONTRACT_ID);
        response.put("status", "COMPLETE");
        response.put("scope", "INPUT_CSV_ONLY");
        response.put("acquisitionMode", CsvFirstLocalEnrichmentExecutor.ACQUISITION_MODE);
        response.put("databaseStateUsed", true);
        response.put("databaseStateScope", "GLOBAL_PUBLIC_INTELLIGENCE_ONLY");
        response.put("tenantDatabaseStateUsed", false);
        response.put("runId", runId.toString());
        response.put("enrichedCsv", ROOT + "/" + runId + "/csv");
        response.put("report", ROOT + "/" + runId + "/report");
        response.put("snapshot", ROOT + "/" + runId + "/snapshot");
        response.put("contextualAnalyses", ROOT + "/" + runId + "/analyses");
        response.put("next", "/assets?tab=managed&setup=1&runId=" + runId);
        sendJson(exchange, 200, response);
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
        byte[] bytes = JsonOutput.object(value).getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=utf-8");
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
