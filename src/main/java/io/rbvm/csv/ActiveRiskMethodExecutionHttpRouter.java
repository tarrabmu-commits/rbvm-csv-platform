package io.rbvm.csv;

import com.sun.net.httpserver.HttpExchange;

import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Exact HTTP transport for V27 active-risk-method execution and immutable binding replay. */
final class ActiveRiskMethodExecutionHttpRouter {
    private static final String EXECUTION_NAMESPACE = "/api/v1/active-risk-method-executions";
    private static final String BINDING_NAMESPACE =
            "/api/v1/active-risk-method-execution-bindings";
    private static final Pattern EXECUTION_ITEM = Pattern.compile(
            "^/api/v1/active-risk-method-executions/([1-9][0-9]*)/"
                    + "([a-f0-9]{64})/([a-f0-9]{64})$"
    );
    private static final Pattern BINDING_ITEM = Pattern.compile(
            "^/api/v1/active-risk-method-execution-bindings/([a-f0-9]{64})$"
    );

    private final ActiveRiskMethodExecutionApi api;

    ActiveRiskMethodExecutionHttpRouter(ActiveRiskMethodExecutionApi api) {
        this.api = Objects.requireNonNull(api, "api");
    }

    static boolean inNamespace(String path) {
        return EXECUTION_NAMESPACE.equals(path)
                || path.startsWith(EXECUTION_NAMESPACE + '/')
                || BINDING_NAMESPACE.equals(path)
                || path.startsWith(BINDING_NAMESPACE + '/');
    }

    static boolean handles(String path) {
        return EXECUTION_ITEM.matcher(path).matches()
                || BINDING_ITEM.matcher(path).matches();
    }

    /** Resolve RBAC before runtime capability lookup so V27 availability is not leaked. */
    static ApiRole requiredRole(HttpExchange exchange, String method) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        String path = exchange.getRequestURI().getPath();

        if (EXECUTION_ITEM.matcher(path).matches()) {
            if (!"POST".equals(method)) {
                exchange.getResponseHeaders().set("Allow", "POST");
                throw new ActiveRiskMethodExecutionApi.ApiProblem(
                        405,
                        "METHOD_NOT_ALLOWED",
                        "Use POST for exact active risk method execution"
                );
            }
            return ApiRole.OPERATOR;
        }
        if (BINDING_ITEM.matcher(path).matches()) {
            if (!"GET".equals(method)) {
                exchange.getResponseHeaders().set("Allow", "GET");
                throw new ActiveRiskMethodExecutionApi.ApiProblem(
                        405,
                        "METHOD_NOT_ALLOWED",
                        "Use GET for exact execution binding replay"
                );
            }
            return ApiRole.VIEWER;
        }
        throw new ActiveRiskMethodExecutionApi.ApiProblem(
                404,
                "NOT_FOUND",
                "The requested active risk method execution route does not exist"
        );
    }

    void routeAuthorized(HttpExchange exchange, String method, AuthPrincipal principal)
            throws IOException {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(principal, "principal");
        rejectQuery(exchange);
        String path = exchange.getRequestURI().getPath();

        Matcher execution = EXECUTION_ITEM.matcher(path);
        if (execution.matches()) {
            if (!"POST".equals(method)) requiredRole(exchange, method);
            rejectBody(
                    exchange,
                    "Execution accepts exact activation and Decision Input identities in the path only"
            );
            send(exchange, api.execute(
                    positiveInteger(execution.group(1), "activationRevision"),
                    execution.group(2),
                    execution.group(3)
            ));
            return;
        }

        Matcher binding = BINDING_ITEM.matcher(path);
        if (binding.matches()) {
            if (!"GET".equals(method)) requiredRole(exchange, method);
            rejectBody(exchange, "Exact execution binding replay does not accept a request body");
            send(exchange, api.getBinding(binding.group(1)));
            return;
        }

        throw new ActiveRiskMethodExecutionApi.ApiProblem(
                404,
                "NOT_FOUND",
                "The requested active risk method execution route does not exist"
        );
    }

    private static int positiveInteger(String value, String field) {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 1) throw new NumberFormatException("not positive");
            return parsed;
        } catch (NumberFormatException exception) {
            throw new ActiveRiskMethodExecutionApi.ApiProblem(
                    400,
                    "INVALID_ACTIVE_RISK_METHOD_EXECUTION_IDENTITY",
                    field + " must be a positive 32-bit integer"
            );
        }
    }

    private static void rejectQuery(HttpExchange exchange) {
        String query = exchange.getRequestURI().getRawQuery();
        if (query != null && !query.isBlank()) {
            throw new ActiveRiskMethodExecutionApi.ApiProblem(
                    400,
                    "INVALID_ACTIVE_RISK_METHOD_EXECUTION_QUERY",
                    "Active risk method execution routes do not accept query parameters"
            );
        }
    }

    private static void rejectBody(HttpExchange exchange, String detail) throws IOException {
        if (exchange.getRequestBody().read() != -1) {
            throw new ActiveRiskMethodExecutionApi.ApiProblem(
                    400,
                    "ACTIVE_RISK_METHOD_EXECUTION_BODY_NOT_ALLOWED",
                    detail
            );
        }
    }

    private static void send(HttpExchange exchange, ActiveRiskMethodExecutionApi.Response response)
            throws IOException {
        response.headers().forEach(exchange.getResponseHeaders()::set);
        byte[] bytes = JsonOutput.pretty(response.body()).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(response.status(), bytes.length);
        exchange.getResponseBody().write(bytes);
    }
}
