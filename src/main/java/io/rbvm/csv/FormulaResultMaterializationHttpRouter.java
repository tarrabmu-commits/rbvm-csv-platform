package io.rbvm.csv;

import com.sun.net.httpserver.HttpExchange;

import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Narrow write-only socket adapter for RBVM_FORMULA_RESULT_MATERIALIZATION_API_V1. */
final class FormulaResultMaterializationHttpRouter {
    private static final String COLLECTION_PATH = "/api/v1/formula-result-materializations";
    private static final Pattern ITEM_PATH = Pattern.compile(
            "^/api/v1/formula-result-materializations/([^/]+)$"
    );

    private final FormulaResultMaterializationApi api;

    FormulaResultMaterializationHttpRouter(FormulaResultMaterializationApi api) {
        this.api = Objects.requireNonNull(api, "api");
    }

    static boolean inNamespace(String path) {
        return COLLECTION_PATH.equals(path) || path.startsWith(COLLECTION_PATH + '/');
    }

    static boolean handles(String path) {
        return ITEM_PATH.matcher(path).matches();
    }

    /** Resolve Operator RBAC before capability lookup so V23 availability is not leaked pre-auth. */
    static ApiRole requiredRole(HttpExchange exchange, String method) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        if (!"POST".equals(method)) {
            exchange.getResponseHeaders().set("Allow", "POST");
            throw new FormulaResultMaterializationApi.ApiProblem(
                    405,
                    "METHOD_NOT_ALLOWED",
                    "Use POST for this route"
            );
        }
        return ApiRole.OPERATOR;
    }

    void routeAuthorized(HttpExchange exchange, String method, AuthPrincipal principal)
            throws IOException {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(principal, "principal");
        if (!"POST".equals(method)) {
            requiredRole(exchange, method);
        }

        String path = exchange.getRequestURI().getPath();
        Matcher item = ITEM_PATH.matcher(path);
        if (!item.matches()) {
            throw new FormulaResultMaterializationApi.ApiProblem(
                    404,
                    "NOT_FOUND",
                    "The requested Formula materialization route does not exist"
            );
        }
        String query = exchange.getRequestURI().getRawQuery();
        if (query != null && !query.isBlank()) {
            throw new FormulaResultMaterializationApi.ApiProblem(
                    400,
                    "INVALID_FORMULA_MATERIALIZATION_REQUEST",
                    "Formula materialization does not accept query parameters"
            );
        }
        if (exchange.getRequestBody().read() != -1) {
            throw new FormulaResultMaterializationApi.ApiProblem(
                    400,
                    "FORMULA_MATERIALIZATION_BODY_NOT_ALLOWED",
                    "Formula materialization accepts the exact Decision Input identity in the path only"
            );
        }
        send(exchange, api.materialize(item.group(1)));
    }

    private static void send(
            HttpExchange exchange,
            FormulaResultMaterializationApi.Response response
    ) throws IOException {
        response.headers().forEach(exchange.getResponseHeaders()::set);
        byte[] bytes = JsonOutput.pretty(response.body()).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(response.status(), bytes.length);
        exchange.getResponseBody().write(bytes);
    }
}
