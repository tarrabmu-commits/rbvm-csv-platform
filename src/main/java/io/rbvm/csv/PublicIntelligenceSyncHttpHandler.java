package io.rbvm.csv;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.rbvm.postgres.PostgresPublicIntelligenceStore;
import io.rbvm.postgres.PostgresPublicIntelligenceSyncJobStore;
import io.rbvm.postgres.PublicIntelligenceSyncCoordinator;
import io.rbvm.postgres.PublicIntelligenceSyncTrigger;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Operator-only asynchronous trigger for one exact public-intelligence provider source. */
public final class PublicIntelligenceSyncHttpHandler implements HttpHandler {
    public static final String CONTRACT_ID = "PUBLIC_INTELLIGENCE_SYNC_HTTP_V1";
    public static final String ROOT = "/api/v1/intelligence/sync";
    private static final Pattern ITEM = Pattern.compile(
            "^/api/v1/intelligence/sync/(NVD|FIRST_EPSS|CISA_KEV|CVE_PROGRAM)$");

    private final Optional<PublicIntelligenceSyncTrigger> trigger;
    private final ApiKeyAuthenticator authenticator;

    public PublicIntelligenceSyncHttpHandler(
            Optional<? extends PublicIntelligenceSyncTrigger> trigger,
            ApiKeyAuthenticator authenticator
    ) {
        Objects.requireNonNull(trigger, "trigger");
        this.trigger = trigger.map(value -> (PublicIntelligenceSyncTrigger) value);
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
            Matcher route = ITEM.matcher(exchange.getRequestURI().getPath());
            if (!route.matches()) {
                problem(exchange, 404, "NOT_FOUND", "The requested intelligence sync route does not exist");
                return;
            }
            requireRole(exchange, ApiRole.OPERATOR);
            if (!"POST".equals(method)) {
                exchange.getResponseHeaders().set("Allow", "POST");
                problem(exchange, 405, "METHOD_NOT_ALLOWED", "Use POST to trigger intelligence synchronization");
                return;
            }
            rejectBody(exchange);

            PostgresPublicIntelligenceStore.Provider provider =
                    PostgresPublicIntelligenceStore.Provider.valueOf(route.group(1));
            String nvdFeed = feed(exchange, provider);
            PublicIntelligenceSyncTrigger sync = trigger.orElseThrow(UnavailableException::new);
            PublicIntelligenceSyncTrigger.Submission submission = sync.submit(
                    provider,
                    nvdFeed,
                    PostgresPublicIntelligenceSyncJobStore.TriggerSource.MANUAL);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("contractId", CONTRACT_ID);
            response.put("jobId", submission.jobId().toString());
            response.put("provider", submission.provider().name());
            response.put("nvdFeed", submission.nvdFeed());
            response.put("status", submission.status());
            response.put("stage", submission.stage());
            response.put("startedAt", submission.startedAt().toString());
            response.put("statusUri", PublicIntelligenceStatusHttpHandler.ROOT);
            exchange.getResponseHeaders().set("Location", PublicIntelligenceStatusHttpHandler.ROOT);
            sendJson(exchange, 202, response);
        } catch (PublicIntelligenceSyncCoordinator.AlreadyRunningException exception) {
            problem(exchange, 409, "INTELLIGENCE_SYNC_ALREADY_RUNNING", exception.getMessage());
        } catch (UnavailableException exception) {
            problem(
                    exchange,
                    503,
                    "INTELLIGENCE_SYNC_UNAVAILABLE",
                    "Public intelligence synchronization requires PostgreSQL V31 and the configured runtime pipeline");
        } catch (IllegalArgumentException exception) {
            problem(exchange, 400, "INVALID_INTELLIGENCE_SYNC_REQUEST", safeDetail(exception));
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (IOException exception) {
            problem(exchange, 503, "INTELLIGENCE_SYNC_START_FAILED", "Public intelligence synchronization could not be started");
        } catch (Exception exception) {
            problem(exchange, 500, "INTERNAL_ERROR", "The intelligence synchronization request failed");
        } finally {
            exchange.close();
        }
    }

    private static String feed(
            HttpExchange exchange,
            PostgresPublicIntelligenceStore.Provider provider
    ) {
        String raw = exchange.getRequestURI().getRawQuery();
        if (raw == null || raw.isBlank()) return provider == PostgresPublicIntelligenceStore.Provider.NVD
                ? "modified"
                : null;
        String selected = null;
        for (String pair : raw.split("&")) {
            if (pair.isBlank()) continue;
            String[] parts = pair.split("=", 2);
            String key = decode(parts[0]);
            String value = parts.length == 2 ? decode(parts[1]) : "";
            if (!"feed".equals(key)) {
                throw new IllegalArgumentException("Only the NVD feed query parameter is supported");
            }
            if (provider != PostgresPublicIntelligenceStore.Provider.NVD) {
                throw new IllegalArgumentException("feed is valid only for provider NVD");
            }
            if (selected != null) throw new IllegalArgumentException("feed may be supplied only once");
            selected = value;
        }
        if (provider == PostgresPublicIntelligenceStore.Provider.NVD) {
            return selected == null || selected.isBlank() ? "modified" : selected;
        }
        return null;
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static void rejectBody(HttpExchange exchange) throws IOException {
        String length = exchange.getRequestHeaders().getFirst("Content-Length");
        if (length != null) {
            try {
                if (Long.parseLong(length) > 0) {
                    throw new IllegalArgumentException("Intelligence sync trigger does not accept a request body");
                }
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("Content-Length is invalid", exception);
            }
        }
        if (exchange.getRequestBody().read() != -1) {
            throw new IllegalArgumentException("Intelligence sync trigger does not accept a request body");
        }
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        Optional<AuthPrincipal> principal = authenticator.authenticate(authorization);
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
        }
    }

    private static String safeDetail(Exception exception) {
        String detail = exception.getMessage();
        if (detail == null || detail.isBlank()) return "Invalid intelligence synchronization request";
        detail = detail.replace('\r', ' ').replace('\n', ' ').replaceAll("\\s+", " ").trim();
        return detail.length() <= 256 ? detail : detail.substring(0, 256);
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
