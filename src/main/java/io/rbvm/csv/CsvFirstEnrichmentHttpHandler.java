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
 * Trusted-local CSV-first public-intelligence transport.
 *
 * The uploaded CSV is the complete scope of one enrichment run. The handler
 * never reads current Cases or tenant database state. It stages the file under
 * a server-owned run directory and invokes the repository's deterministic
 * enrich-uploaded-csv.py orchestrator without a shell.
 */
public final class CsvFirstEnrichmentHttpHandler implements HttpHandler {
    public static final String CONTRACT_ID = "CSV_FIRST_PUBLIC_INTELLIGENCE_HTTP_V1";
    private static final Pattern ARTIFACT_PATH = Pattern.compile(
            "^/api/v1/csv-first-enrichments/([0-9a-fA-F-]{36})/(csv|report|snapshot)$");
    private static final String ROOT = "/api/v1/csv-first-enrichments";
    private static final Duration PROCESS_TIMEOUT = Duration.ofMinutes(10);
    private static final int MAX_PROCESS_OUTPUT_BYTES = 64 * 1024;

    private final Path dataDirectory;
    private final Path script;
    private final Path cacheDirectory;
    private final String python;
    private final long maximumUploadBytes;
    private final ApiKeyAuthenticator authenticator;

    public CsvFirstEnrichmentHttpHandler(
            Path dataDirectory,
            long maximumUploadBytes,
            ApiKeyAuthenticator authenticator
    ) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        this.maximumUploadBytes = maximumUploadBytes;
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        String repositoryRoot = System.getenv().getOrDefault("RBVM_REPOSITORY_ROOT", ".");
        Path root = Path.of(repositoryRoot).toAbsolutePath().normalize();
        this.script = root.resolve("scripts/enrich-uploaded-csv.py").normalize();
        this.cacheDirectory = this.dataDirectory.resolve("public-cve-intel-cache").normalize();
        this.python = System.getenv().getOrDefault("RBVM_PYTHON", "python3");
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
            Matcher matcher = ARTIFACT_PATH.matcher(path);
            if (!matcher.matches()) {
                problem(exchange, 404, "NOT_FOUND", "The requested CSV-first enrichment route does not exist");
                return;
            }
            requireRole(exchange, ApiRole.VIEWER);
            if (!"GET".equals(method)) {
                methodNotAllowed(exchange, "GET");
                return;
            }
            UUID runId;
            try {
                runId = UUID.fromString(matcher.group(1));
            } catch (IllegalArgumentException exception) {
                problem(exchange, 400, "INVALID_RUN_ID", "Invalid CSV-first enrichment run identifier");
                return;
            }
            artifact(exchange, runId, matcher.group(2));
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            exception.printStackTrace(System.err);
            problem(exchange, 500, "INTERNAL_ERROR", "The CSV-first enrichment request could not be completed");
        } finally {
            exchange.close();
        }
    }

    private void create(HttpExchange exchange) throws IOException {
        if (!Files.isRegularFile(script) || Files.isSymbolicLink(script)) {
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
        long length = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (length > maximumUploadBytes) {
            problem(exchange, 413, "UPLOAD_TOO_LARGE", "CSV exceeds the configured upload limit");
            return;
        }

        UUID runId = UUID.randomUUID();
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        if (!run.startsWith(runs)) {
            throw new IOException("invalid run directory");
        }
        Files.createDirectories(run);
        Path input = run.resolve("input.csv");
        Path output = run.resolve("enriched.csv");
        Path snapshot = run.resolve("public-intel.json");
        Path report = run.resolve("report.json");
        Path collectorReport = run.resolve("collector-report.json");
        Path processLog = run.resolve("process.log");

        try (InputStream body = exchange.getRequestBody();
             OutputStream staged = Files.newOutputStream(input)) {
            copyBounded(body, staged, maximumUploadBytes);
        } catch (UploadTooLargeException exception) {
            deleteTree(run);
            problem(exchange, 413, "UPLOAD_TOO_LARGE", exception.getMessage());
            return;
        }

        ProcessBuilder builder = new ProcessBuilder(
                python,
                script.toString(),
                input.toString(),
                output.toString(),
                "--snapshot-output", snapshot.toString(),
                "--report", report.toString(),
                "--collector-report", collectorReport.toString(),
                "--cache-dir", cacheDirectory.toString()
        );
        builder.directory(script.getParent().getParent().toFile());
        builder.redirectErrorStream(true);
        builder.redirectOutput(processLog.toFile());
        Process process = builder.start();
        boolean finished;
        try {
            finished = process.waitFor(PROCESS_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            deleteTree(run);
            problem(exchange, 503, "CSV_FIRST_ENRICHMENT_INTERRUPTED", "CSV-first enrichment was interrupted");
            return;
        }
        if (!finished) {
            process.destroyForcibly();
            deleteTree(run);
            problem(exchange, 504, "CSV_FIRST_ENRICHMENT_TIMEOUT", "CSV-first enrichment exceeded the execution limit");
            return;
        }
        if (process.exitValue() != 0 || !Files.isRegularFile(output) || !Files.isRegularFile(report)) {
            byte[] processOutput = Files.isRegularFile(processLog)
                    ? Files.readAllBytes(processLog)
                    : new byte[0];
            String diagnostic = new String(
                    processOutput,
                    0,
                    Math.min(processOutput.length, MAX_PROCESS_OUTPUT_BYTES),
                    StandardCharsets.UTF_8
            ).trim();
            deleteTree(run);
            problem(exchange, 422, "CSV_FIRST_ENRICHMENT_FAILED",
                    diagnostic.isBlank() ? "CSV-first enrichment failed" : diagnostic);
            return;
        }
        Files.deleteIfExists(processLog);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("contractId", CONTRACT_ID);
        response.put("status", "COMPLETE");
        response.put("scope", "INPUT_CSV_ONLY");
        response.put("databaseStateUsed", false);
        response.put("runId", runId.toString());
        response.put("enrichedCsv", ROOT + "/" + runId + "/csv");
        response.put("report", ROOT + "/" + runId + "/report");
        response.put("snapshot", ROOT + "/" + runId + "/snapshot");
        response.put("next", "/assets?tab=managed&setup=1&runId=" + runId);
        sendJson(exchange, 200, response);
    }

    private void artifact(HttpExchange exchange, UUID runId, String type) throws IOException {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        if (!run.startsWith(runs)) {
            problem(exchange, 400, "INVALID_RUN_ID", "Invalid CSV-first enrichment run identifier");
            return;
        }
        Path file;
        String contentType;
        String downloadName;
        switch (type) {
            case "csv" -> {
                file = run.resolve("enriched.csv");
                contentType = "text/csv; charset=utf-8";
                downloadName = "rbvm-enriched-" + runId + ".csv";
            }
            case "report" -> {
                file = run.resolve("report.json");
                contentType = "application/json; charset=utf-8";
                downloadName = "rbvm-enrichment-report-" + runId + ".json";
            }
            case "snapshot" -> {
                file = run.resolve("public-intel.json");
                contentType = "application/json; charset=utf-8";
                downloadName = "rbvm-public-intel-" + runId + ".json";
            }
            default -> throw new IllegalStateException("unexpected artifact type");
        }
        if (!Files.isRegularFile(file) || Files.isSymbolicLink(file)) {
            problem(exchange, 404, "ARTIFACT_NOT_FOUND", "CSV-first enrichment artifact does not exist");
            return;
        }
        exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + downloadName + "\"");
        sendBytes(exchange, 200, contentType, Files.readAllBytes(file));
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
            if (total > maximumBytes) throw new UploadTooLargeException("CSV exceeds the configured upload limit");
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

    private static final class UploadTooLargeException extends Exception {
        private UploadTooLargeException(String message) { super(message); }
    }
}
