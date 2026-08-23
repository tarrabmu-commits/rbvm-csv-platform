package io.rbvm.csv;

import com.sun.net.httpserver.HttpExchange;

import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Exact HTTP transport for immutable primary risk-method selection policies. */
final class RiskMethodSelectionPolicyHttpRouter {
    private static final String POLICY_NAMESPACE = "/api/v1/risk-method-selection-policies";
    private static final String INSTALLATION_NAMESPACE =
            "/api/v1/risk-method-selection-policy-installations";
    private static final Pattern POLICY_ITEM = Pattern.compile(
            "^/api/v1/risk-method-selection-policies/([1-9][0-9]*)/([a-f0-9]{64})$"
    );
    private static final Pattern INSTALLATION_ITEM = Pattern.compile(
            "^/api/v1/risk-method-selection-policy-installations/([1-9][0-9]*)/"
                    + "(RBVM_FORMULA|STANDARD_DERIVED)/([^/]+)/([1-9][0-9]*)/([a-f0-9]{64})$"
    );

    private final RiskMethodSelectionPolicyApi api;

    RiskMethodSelectionPolicyHttpRouter(RiskMethodSelectionPolicyApi api) {
        this.api = Objects.requireNonNull(api, "api");
    }

    static boolean inNamespace(String path) {
        return POLICY_NAMESPACE.equals(path)
                || path.startsWith(POLICY_NAMESPACE + '/')
                || INSTALLATION_NAMESPACE.equals(path)
                || path.startsWith(INSTALLATION_NAMESPACE + '/');
    }

    static boolean handles(String path) {
        return POLICY_ITEM.matcher(path).matches()
                || INSTALLATION_ITEM.matcher(path).matches();
    }

    /** Resolve route-specific RBAC before capability lookup so V25 availability is not leaked. */
    static ApiRole requiredRole(HttpExchange exchange, String method) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        String path = exchange.getRequestURI().getPath();

        if (INSTALLATION_ITEM.matcher(path).matches()) {
            if (!"POST".equals(method)) {
                exchange.getResponseHeaders().set("Allow", "POST");
                throw new RiskMethodSelectionPolicyApi.ApiProblem(
                        405,
                        "METHOD_NOT_ALLOWED",
                        "Use POST for risk method selection policy installation"
                );
            }
            return ApiRole.OPERATOR;
        }

        if (POLICY_ITEM.matcher(path).matches()) {
            if (!"GET".equals(method)) {
                exchange.getResponseHeaders().set("Allow", "GET");
                throw new RiskMethodSelectionPolicyApi.ApiProblem(
                        405,
                        "METHOD_NOT_ALLOWED",
                        "Use GET for exact risk method selection policy lookup"
                );
            }
            return ApiRole.VIEWER;
        }

        throw new RiskMethodSelectionPolicyApi.ApiProblem(
                404,
                "NOT_FOUND",
                "The requested risk method selection policy route does not exist"
        );
    }

    void routeAuthorized(HttpExchange exchange, String method, AuthPrincipal principal)
            throws IOException {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(principal, "principal");
        String path = exchange.getRequestURI().getPath();
        rejectQuery(exchange);

        Matcher policy = POLICY_ITEM.matcher(path);
        if (policy.matches()) {
            if (!"GET".equals(method)) requiredRole(exchange, method);
            rejectBody(exchange, "Exact policy lookup does not accept a request body");
            send(exchange, api.get(
                    positiveInteger(policy.group(1), "revision"),
                    policy.group(2)
            ));
            return;
        }

        Matcher installation = INSTALLATION_ITEM.matcher(path);
        if (installation.matches()) {
            if (!"POST".equals(method)) requiredRole(exchange, method);
            rejectBody(exchange, "Policy installation accepts exact identities in the path only");
            send(exchange, api.install(
                    positiveInteger(installation.group(1), "revision"),
                    installation.group(2),
                    installation.group(3),
                    positiveInteger(installation.group(4), "methodVersion"),
                    installation.group(5)
            ));
            return;
        }

        throw new RiskMethodSelectionPolicyApi.ApiProblem(
                404,
                "NOT_FOUND",
                "The requested risk method selection policy route does not exist"
        );
    }

    private static int positiveInteger(String value, String field) {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 1) throw new NumberFormatException("not positive");
            return parsed;
        } catch (NumberFormatException exception) {
            throw new RiskMethodSelectionPolicyApi.ApiProblem(
                    400,
                    "INVALID_RISK_METHOD_SELECTION_POLICY_IDENTITY",
                    field + " must be a positive 32-bit integer"
            );
        }
    }

    private static void rejectQuery(HttpExchange exchange) {
        String query = exchange.getRequestURI().getRawQuery();
        if (query != null && !query.isBlank()) {
            throw new RiskMethodSelectionPolicyApi.ApiProblem(
                    400,
                    "INVALID_RISK_METHOD_SELECTION_POLICY_QUERY",
                    "Risk method selection policy routes do not accept query parameters"
            );
        }
    }

    private static void rejectBody(HttpExchange exchange, String detail) throws IOException {
        if (exchange.getRequestBody().read() != -1) {
            throw new RiskMethodSelectionPolicyApi.ApiProblem(
                    400,
                    "RISK_METHOD_SELECTION_POLICY_BODY_NOT_ALLOWED",
                    detail
            );
        }
    }

    private static void send(HttpExchange exchange, RiskMethodSelectionPolicyApi.Response response)
            throws IOException {
        response.headers().forEach(exchange.getResponseHeaders()::set);
        byte[] bytes = JsonOutput.pretty(response.body()).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(response.status(), bytes.length);
        exchange.getResponseBody().write(bytes);
    }
}
