package io.rbvm.csv;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.rbvm.postgres.CanonicalImportFindingExporter;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Read-only exact manifest for canonical Findings materialized from one committed import. */
public final class CanonicalImportFindingHttpHandler implements HttpHandler {
    public static final String CONTRACT_ID = "CANONICAL_IMPORT_FINDING_MANIFEST_HTTP_V1";
    private static final Pattern PATH = Pattern.compile(
            "^/api/v1/canonical-imports/([0-9a-fA-F-]{36})/findings\\.csv$");

    private final Optional<CanonicalImportFindingExporter> exporter;
    private final ApiKeyAuthenticator authenticator;

    public CanonicalImportFindingHttpHandler(
            Optional<CanonicalImportFindingExporter> exporter,
            ApiKeyAuthenticator authenticator
    ) {
        this.exporter = Objects.requireNonNull(exporter, "exporter");
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            Matcher matcher = PATH.matcher(exchange.getRequestURI().getPath());
            if (!matcher.matches()) {
                problem(exchange, 404, "NOT_FOUND", "The requested canonical import Finding manifest route does not exist");
                return;
            }
            requireRole(exchange, ApiRole.VIEWER);
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
            if (!"GET".equals(method)) {
                exchange.getResponseHeaders().set("Allow", "GET");
                problem(exchange, 405, "METHOD_NOT_ALLOWED", "Use GET for this resource");
                return;
            }
            String query = exchange.getRequestURI().getRawQuery();
            if (query != null && !query.isBlank()) {
                problem(exchange, 400, "INVALID_QUERY", "Canonical import Finding manifest does not accept query parameters");
                return;
            }

            UUID importId;
            try {
                importId = UUID.fromString(matcher.group(1));
            } catch (IllegalArgumentException exception) {
                problem(exchange, 400, "INVALID_IMPORT_ID", "Invalid canonical import identifier");
                return;
            }

            CanonicalImportFindingExporter available = exporter.orElse(null);
            if (available == null) {
                problem(exchange, 503, "CANONICAL_FINDING_MANIFEST_UNAVAILABLE",
                        "Canonical import Finding manifest requires the PostgreSQL canonical projection");
                return;
            }
            Optional<byte[]> manifest = available.exportCsv(importId);
            if (manifest.isEmpty()) {
                problem(exchange, 404, "COMPLETED_IMPORT_NOT_FOUND",
                        "No completed canonical import exists for this import identifier");
                return;
            }

            Headers headers = exchange.getResponseHeaders();
            headers.set("Content-Disposition", "attachment; filename=\"rbvm-findings-" + importId + ".csv\"");
            headers.set("X-RBVM-Contract", CONTRACT_ID);
            headers.set("X-RBVM-Import-Id", importId.toString());
            sendBytes(exchange, 200, "text/csv; charset=utf-8", manifest.get());
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            problem(exchange, 500, "INTERNAL_ERROR", "Canonical import Finding manifest could not be exported");
        } finally {
            exchange.close();
        }
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        Optional<AuthPrincipal> principal = authenticator.authenticate(authorization);
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
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
