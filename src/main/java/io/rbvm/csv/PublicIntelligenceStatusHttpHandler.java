package io.rbvm.csv;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.rbvm.postgres.PublicIntelligenceStatusReader;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Read-only operator status for the four public-intelligence providers. */
public final class PublicIntelligenceStatusHttpHandler implements HttpHandler {
    public static final String CONTRACT_ID = "PUBLIC_INTELLIGENCE_STATUS_HTTP_V1";
    public static final String ROOT = "/api/v1/intelligence/status";

    private final Optional<PublicIntelligenceStatusReader> reader;
    private final ApiKeyAuthenticator authenticator;

    public PublicIntelligenceStatusHttpHandler(
            Optional<? extends PublicIntelligenceStatusReader> reader,
            ApiKeyAuthenticator authenticator
    ) {
        Objects.requireNonNull(reader, "reader");
        this.reader = reader.map(value -> (PublicIntelligenceStatusReader) value);
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
            if (!ROOT.equals(path)) {
                problem(exchange, 404, "NOT_FOUND", "The requested intelligence status route does not exist");
                return;
            }
            requireRole(exchange, ApiRole.VIEWER);
            if (!"GET".equals(method)) {
                exchange.getResponseHeaders().set("Allow", "GET");
                problem(exchange, 405, "METHOD_NOT_ALLOWED", "HTTP method is not allowed for this resource");
                return;
            }
            PublicIntelligenceStatusReader statusReader = reader.orElseThrow(() ->
                    new UnavailableException());
            List<Map<String, Object>> providers = new ArrayList<>();
            for (PublicIntelligenceStatusReader.ProviderStatus status : statusReader.readStatus()) {
                providers.add(provider(status));
            }
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("contractId", CONTRACT_ID);
            response.put("generatedAt", Instant.now().toString());
            response.put("providers", providers);
            sendJson(exchange, 200, response);
        } catch (UnavailableException exception) {
            problem(
                    exchange,
                    503,
                    "INTELLIGENCE_STATUS_UNAVAILABLE",
                    "Public intelligence status requires PostgreSQL schema version 31 or newer");
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (IOException exception) {
            problem(exchange, 503, "INTELLIGENCE_STATUS_READ_FAILED",
                    "Public intelligence status could not be read");
        } catch (Exception exception) {
            problem(exchange, 500, "INTERNAL_ERROR", "The intelligence status request failed");
        } finally {
            exchange.close();
        }
    }

    private Map<String, Object> provider(PublicIntelligenceStatusReader.ProviderStatus status) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("provider", status.provider().name());
        value.put("neverAttempted", status.latestJobId() == null);
        value.put("neverSucceeded", status.latestSuccessId() == null);

        Map<String, Object> job = new LinkedHashMap<>();
        job.put("id", text(status.latestJobId()));
        job.put("triggerSource", status.latestJobTriggerSource());
        job.put("status", status.latestJobStatus());
        job.put("stage", status.latestJobStage());
        job.put("startedAt", text(status.latestJobStartedAt()));
        job.put("updatedAt", text(status.latestJobUpdatedAt()));
        job.put("completedAt", text(status.latestJobCompletedAt()));
        job.put("sourceUri", status.latestJobSourceUri());
        job.put("sourceVersion", status.latestJobSourceVersion());
        job.put("sourceSha256", status.latestJobSourceSha256());
        job.put("syncRunId", text(status.latestJobSyncRunId()));
        job.put("errorCode", status.latestJobErrorCode());
        job.put("errorDetail", status.latestJobErrorDetail());
        value.put("latestJob", job);

        Map<String, Object> success = new LinkedHashMap<>();
        success.put("syncRunId", text(status.latestSuccessId()));
        success.put("syncMode", status.latestSuccessMode());
        success.put("sourceUri", status.latestSuccessSourceUri());
        success.put("sourceVersion", status.latestSuccessSourceVersion());
        success.put("sourceSha256", status.latestSuccessSourceSha256());
        success.put("sourcePublishedAt", text(status.latestSuccessSourcePublishedAt()));
        success.put("observedAt", text(status.latestSuccessObservedAt()));
        success.put("completedAt", text(status.latestSuccessCompletedAt()));
        success.put("recordCount", status.latestSuccessRecordCount());
        value.put("lastSuccess", success);
        return value;
    }

    private static String text(Object value) {
        return value == null ? null : value.toString();
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        Optional<AuthPrincipal> principal = authenticator.authenticate(authorization);
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
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

    private static void sendJson(HttpExchange exchange, int status, Map<String, Object> value)
            throws IOException {
        byte[] bytes = JsonOutput.object(value).getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=utf-8");
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-RBVM-Contract", CONTRACT_ID);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private static final class UnavailableException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
}
