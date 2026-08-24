package io.rbvm.csv;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.rbvm.postgres.CanonicalMvpPriorityStore;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Read-only latest explicitly materialized canonical MVP priority for one Finding. */
public final class CanonicalMvpPriorityReadHttpHandler implements HttpHandler {
    public static final String CONTRACT_ID = "CANONICAL_MVP_PRIORITY_READ_HTTP_V1";
    private static final Pattern PATH = Pattern.compile(
            "^/api/v1/canonical-mvp-priorities/findings/([a-f0-9]{64}|[0-9a-fA-F-]{36})$");

    private final Optional<CanonicalMvpPriorityStore> store;
    private final ApiKeyAuthenticator authenticator;

    public CanonicalMvpPriorityReadHttpHandler(
            Optional<CanonicalMvpPriorityStore> store,
            ApiKeyAuthenticator authenticator
    ) {
        this.store = Objects.requireNonNull(store, "store");
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            Matcher matcher = PATH.matcher(exchange.getRequestURI().getPath());
            if (!matcher.matches()) {
                problem(exchange, 404, "NOT_FOUND", "The requested canonical MVP-priority read route does not exist");
                return;
            }
            requireRole(exchange, ApiRole.VIEWER);
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Allow", "GET");
                problem(exchange, 405, "METHOD_NOT_ALLOWED", "HTTP method is not allowed for this resource");
                return;
            }
            CanonicalMvpPriorityStore access = store.orElse(null);
            if (access == null) {
                problem(exchange, 503, "CANONICAL_MVP_PRIORITY_PERSISTENCE_UNAVAILABLE",
                        "Canonical MVP priority requires PostgreSQL schema version 29 or newer");
                return;
            }
            Optional<CanonicalMvpPriorityStore.PriorityView> result = access.latestForFinding(matcher.group(1));
            if (result.isEmpty()) {
                problem(exchange, 404, "CANONICAL_PRIORITY_NOT_MATERIALIZED",
                        "No explicit canonical MVP priority has been materialized for this Finding");
                return;
            }
            sendJson(exchange, 200, view(result.get()));
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            exception.printStackTrace(System.err);
            problem(exchange, 500, "INTERNAL_ERROR", "Canonical MVP priority could not be read");
        } finally {
            exchange.close();
        }
    }

    private static Map<String, Object> view(CanonicalMvpPriorityStore.PriorityView result) {
        Map<String, Object> inputs = new LinkedHashMap<>();
        inputs.put("kevListed", result.kevListed());
        inputs.put("internetFacing", result.internetFacing());
        inputs.put("assetCriticality", result.assetCriticality());
        inputs.put("epssProbability", result.epssProbability());
        inputs.put("contextualCvssV4", result.contextualCvssV4());
        inputs.put("semantics", "ARTIFACT_BOUND_ADMITTED_INPUTS_NOT_NEW_CANONICAL_EVIDENCE");

        Map<String, Object> provenance = new LinkedHashMap<>();
        provenance.put("importId", result.importId().toString());
        provenance.put("runId", result.csvRunId().toString());
        provenance.put("analysisId", result.analysisId().toString());
        provenance.put("sourceRowNumbers", result.sourceRowNumbers());
        provenance.put("sourceCsvSha256", result.sourceCsvSha256());
        provenance.put("priorityCsvSha256", result.priorityCsvSha256());
        provenance.put("resultSha256", result.resultSha256());
        provenance.put("materializedAt", result.materializedAt().toString());
        provenance.put("association", "EXACT_IMPORT_SOURCE_ROW_TO_OBSERVATION_TO_EXPOSURE_ONLY");

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("contractId", CONTRACT_ID);
        output.put("findingId", result.findingId());
        output.put("methodId", CanonicalMvpPriorityStore.METHOD_ID);
        output.put("methodSha256", CanonicalMvpPriorityStore.METHOD_SHA256);
        output.put("classification", "RBVM_POLICY");
        output.put("prioritySemantics", "RELATIVE_TREATMENT_PRIORITY_PARETO_FRONT_WITHIN_INPUT_SET");
        output.put("status", result.status());
        output.put("front", result.front());
        output.put("dominatedBy", result.dominatedBy());
        output.put("dominates", result.dominates());
        output.put("blockers", result.blockers());
        output.put("explanation", result.explanation());
        output.put("inputs", inputs);
        output.put("provenance", provenance);
        output.put("organizationalRisk", "NON_COMPUTABLE");
        return output;
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        Optional<AuthPrincipal> principal = authenticator.authenticate(
                exchange.getRequestHeaders().getFirst("Authorization"));
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
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream body = exchange.getResponseBody()) { body.write(bytes); }
    }
}
