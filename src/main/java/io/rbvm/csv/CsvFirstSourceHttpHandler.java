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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Read-only transport for the exact original CSV-first upload bytes. */
public final class CsvFirstSourceHttpHandler implements HttpHandler {
    public static final String CONTRACT_ID = "CSV_FIRST_SOURCE_ARTIFACT_HTTP_V1";
    private static final String ROOT = "/api/v1/csv-first-sources";
    private static final Pattern SOURCE_PATH = Pattern.compile(
            "^/api/v1/csv-first-sources/([0-9a-fA-F-]{36})$");

    private final Path dataDirectory;
    private final ApiKeyAuthenticator authenticator;

    public CsvFirstSourceHttpHandler(Path dataDirectory, ApiKeyAuthenticator authenticator) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
            Matcher matcher = SOURCE_PATH.matcher(exchange.getRequestURI().getPath());
            if (!matcher.matches()) {
                problem(exchange, 404, "NOT_FOUND", "The requested CSV-first source route does not exist");
                return;
            }
            requireRole(exchange, ApiRole.VIEWER);
            if (!"GET".equals(method)) {
                exchange.getResponseHeaders().set("Allow", "GET");
                problem(exchange, 405, "METHOD_NOT_ALLOWED", "HTTP method is not allowed for this resource");
                return;
            }

            UUID runId;
            try {
                runId = UUID.fromString(matcher.group(1));
            } catch (IllegalArgumentException exception) {
                problem(exchange, 400, "INVALID_RUN_ID", "Invalid CSV-first enrichment run identifier");
                return;
            }

            Path source = sourcePath(runId);
            if (!Files.isRegularFile(source) || Files.isSymbolicLink(source)) {
                problem(exchange, 404, "RUN_SOURCE_NOT_FOUND", "The original CSV-first source artifact does not exist");
                return;
            }
            byte[] bytes = Files.readAllBytes(source);
            Headers headers = exchange.getResponseHeaders();
            headers.set("Content-Disposition", "attachment; filename=\"rbvm-source-" + runId + ".csv\"");
            headers.set("X-RBVM-Contract", CONTRACT_ID);
            headers.set("X-RBVM-Run-Id", runId.toString());
            headers.set("X-RBVM-Source-SHA256", sha256(bytes));
            sendBytes(exchange, 200, "text/csv; charset=utf-8", bytes);
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            problem(exchange, 500, "INTERNAL_ERROR", "The CSV-first source artifact could not be read");
        } finally {
            exchange.close();
        }
    }

    private Path sourcePath(UUID runId) throws IOException {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        if (!run.startsWith(runs)) throw new IOException("invalid run directory");
        Path source = run.resolve("input.csv").normalize();
        if (!source.startsWith(run)) throw new IOException("invalid source path");
        return source;
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        Optional<AuthPrincipal> principal = authenticator.authenticate(authorization);
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
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
}
