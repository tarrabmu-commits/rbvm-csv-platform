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
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Run-scoped local persistence transport for the customer-declared asset bundle.
 *
 * <p>This endpoint stores the exact JSON artifact supplied by the customer UI.
 * It deliberately does not infer, normalize, or translate customer evidence.
 * Semantic validation remains owned by the versioned customer-bundle contract.
 */
public final class CsvFirstCustomerAssetBundleHttpHandler implements HttpHandler {
    public static final String ROOT = "/api/v1/csv-first-customer-assets";
    private static final String ARTIFACT_NAME = "customer-assets-v4.json";
    private static final Pattern ITEM_PATH = Pattern.compile(
            "^" + ROOT + "/([0-9a-fA-F-]{36})$");

    private final Path dataDirectory;
    private final long maximumUploadBytes;
    private final ApiKeyAuthenticator authenticator;

    public CsvFirstCustomerAssetBundleHttpHandler(
            Path dataDirectory,
            long maximumUploadBytes,
            ApiKeyAuthenticator authenticator
    ) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        if (maximumUploadBytes < 1) {
            throw new IllegalArgumentException("maximumUploadBytes must be positive");
        }
        this.maximumUploadBytes = maximumUploadBytes;
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            Matcher matcher = ITEM_PATH.matcher(exchange.getRequestURI().getPath());
            if (!matcher.matches()) {
                problem(exchange, 404, "NOT_FOUND", "Customer asset bundle endpoint not found");
                return;
            }

            UUID runId;
            try {
                runId = UUID.fromString(matcher.group(1));
            } catch (IllegalArgumentException exception) {
                problem(exchange, 400, "INVALID_RUN_ID", "runId must be a UUID");
                return;
            }

            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
            switch (method) {
                case "GET" -> {
                    requireRole(exchange, ApiRole.VIEWER);
                    read(exchange, runId);
                }
                case "PUT" -> {
                    requireRole(exchange, ApiRole.OPERATOR);
                    write(exchange, runId);
                }
                default -> {
                    exchange.getResponseHeaders().set("Allow", "GET, PUT");
                    problem(exchange, 405, "METHOD_NOT_ALLOWED", "Use GET or PUT");
                }
            }
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            exception.printStackTrace(System.err);
            problem(exchange, 500, "INTERNAL_ERROR", "Customer asset bundle request failed");
        } finally {
            exchange.close();
        }
    }

    private void read(HttpExchange exchange, UUID runId) throws IOException {
        Path runDirectory = existingRunDirectory(runId);
        if (runDirectory == null) {
            problem(exchange, 404, "RUN_NOT_FOUND", "CSV-first enrichment run was not found");
            return;
        }

        Path artifact = runDirectory.resolve(ARTIFACT_NAME).normalize();
        if (!Files.isRegularFile(artifact)) {
            problem(exchange, 404, "CUSTOMER_ASSET_BUNDLE_NOT_FOUND",
                    "No customer asset bundle has been saved for this run");
            return;
        }

        byte[] bytes = Files.readAllBytes(artifact);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=utf-8");
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("Content-Disposition", "inline; filename=\"" + ARTIFACT_NAME + "\"");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private void write(HttpExchange exchange, UUID runId) throws IOException {
        Path runDirectory = existingRunDirectory(runId);
        if (runDirectory == null) {
            problem(exchange, 404, "RUN_NOT_FOUND", "CSV-first enrichment run was not found");
            return;
        }

        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isJsonContentType(contentType)) {
            problem(exchange, 415, "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be application/json");
            return;
        }

        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (contentLength > maximumUploadBytes) {
            problem(exchange, 413, "UPLOAD_TOO_LARGE",
                    "Customer asset bundle exceeds the configured upload limit");
            return;
        }

        Path artifact = runDirectory.resolve(ARTIFACT_NAME).normalize();
        Path staged = Files.createTempFile(runDirectory, ".customer-assets-", ".json.tmp");
        long bytesWritten;
        try {
            try (InputStream input = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(staged)) {
                bytesWritten = copyBounded(input, output, maximumUploadBytes);
            }
            if (bytesWritten == 0) {
                Files.deleteIfExists(staged);
                problem(exchange, 400, "EMPTY_BUNDLE", "Customer asset bundle must not be empty");
                return;
            }
            replaceAtomically(staged, artifact);
        } catch (UploadTooLargeException exception) {
            Files.deleteIfExists(staged);
            problem(exchange, 413, "UPLOAD_TOO_LARGE",
                    "Customer asset bundle exceeds the configured upload limit");
            return;
        } catch (IOException exception) {
            Files.deleteIfExists(staged);
            throw exception;
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "SAVED");
        response.put("runId", runId.toString());
        response.put("artifact", ROOT + "/" + runId);
        response.put("fileName", ARTIFACT_NAME);
        response.put("bytes", bytesWritten);
        response.put("semantics", "EXACT_CUSTOMER_DECLARED_BUNDLE_NO_INFERENCE");
        sendJson(exchange, 200, response);
    }

    private Path existingRunDirectory(UUID runId) {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        if (!run.startsWith(runs) || !Files.isDirectory(run)) return null;
        return run;
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        Optional<AuthPrincipal> principal = authenticator.authenticate(authorization);
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
        }
    }

    private static boolean isJsonContentType(String value) {
        if (value == null) return false;
        String normalized = value.toLowerCase(Locale.ROOT).split(";", 2)[0].trim();
        return "application/json".equals(normalized);
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

    private static long copyBounded(InputStream input, OutputStream output, long maximumBytes)
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
        return total;
    }

    private static void replaceAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(source, target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void problem(HttpExchange exchange, int status, String code, String detail)
            throws IOException {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("type", "about:blank");
        value.put("title", code);
        value.put("status", status);
        value.put("detail", detail);
        sendJson(exchange, status, value);
    }

    private static void sendJson(HttpExchange exchange, int status, Map<String, ?> value)
            throws IOException {
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
