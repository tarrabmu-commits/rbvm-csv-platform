package io.rbvm.csv;

import com.sun.net.httpserver.HttpExchange;

import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Narrow read-only socket adapter for RBVM_FORMULA_RESULT_API_V1. */
final class FormulaResultHttpRouter {
    private static final String COLLECTION_PATH = "/api/v1/formula-results";
    private static final Pattern ITEM_PATH = Pattern.compile(
            "^/api/v1/formula-results/([^/]+)$"
    );

    private final FormulaResultApi api;

    FormulaResultHttpRouter(FormulaResultApi api) {
        this.api = Objects.requireNonNull(api, "api");
    }

    static boolean inNamespace(String path) {
        return COLLECTION_PATH.equals(path) || path.startsWith(COLLECTION_PATH + '/');
    }

    static boolean handles(String path) {
        return COLLECTION_PATH.equals(path) || ITEM_PATH.matcher(path).matches();
    }

    /** Resolve Viewer RBAC before capability lookup so V23 availability is not leaked pre-auth. */
    static ApiRole requiredRole(HttpExchange exchange, String method) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        if (!"GET".equals(method)) {
            exchange.getResponseHeaders().set("Allow", "GET");
            throw new FormulaResultApi.ApiProblem(
                    405,
                    "METHOD_NOT_ALLOWED",
                    "Use GET for this route"
            );
        }
        return ApiRole.VIEWER;
    }

    void routeAuthorized(HttpExchange exchange, String method, AuthPrincipal principal)
            throws IOException {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(principal, "principal");
        if (!"GET".equals(method)) {
            requiredRole(exchange, method);
        }

        String path = exchange.getRequestURI().getPath();
        if (COLLECTION_PATH.equals(path)) {
            Map<String, String> query = parseParameters(exchange.getRequestURI().getRawQuery());
            rejectUnknown(query, Set.of("inputSnapshotSha256", "formulaSha256"));
            String snapshotSha = required(query, "inputSnapshotSha256");
            String formulaSha = required(query, "formulaSha256");
            send(exchange, api.getByInputSnapshotAndFormula(snapshotSha, formulaSha));
            return;
        }

        Matcher item = ITEM_PATH.matcher(path);
        if (!item.matches()) {
            throw new FormulaResultApi.ApiProblem(
                    404,
                    "NOT_FOUND",
                    "The requested Formula result route does not exist"
            );
        }
        String rawQuery = exchange.getRequestURI().getRawQuery();
        if (rawQuery != null && !rawQuery.isBlank()) {
            throw new FormulaResultApi.ApiProblem(
                    400,
                    "INVALID_FORMULA_RESULT_QUERY",
                    "Exact explanation lookup does not accept query parameters"
            );
        }
        send(exchange, api.getByExplanationSha256(item.group(1)));
    }

    private static Map<String, String> parseParameters(String encoded) {
        Map<String, String> output = new LinkedHashMap<>();
        if (encoded == null || encoded.isBlank()) return output;
        for (String parameter : encoded.split("&")) {
            String[] pair = parameter.split("=", 2);
            String name;
            String value;
            try {
                name = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                value = URLDecoder.decode(pair.length == 2 ? pair[1] : "", StandardCharsets.UTF_8);
            } catch (IllegalArgumentException exception) {
                throw new FormulaResultApi.ApiProblem(
                        400,
                        "INVALID_FORMULA_RESULT_QUERY",
                        "Formula result query parameters contain invalid encoding"
                );
            }
            if (name.isBlank()) {
                throw new FormulaResultApi.ApiProblem(
                        400,
                        "INVALID_FORMULA_RESULT_QUERY",
                        "Formula result query parameter name cannot be empty"
                );
            }
            if (output.putIfAbsent(name, value) != null) {
                throw new FormulaResultApi.ApiProblem(
                        400,
                        "INVALID_FORMULA_RESULT_QUERY",
                        "Duplicate Formula result query parameter: " + name
                );
            }
        }
        return output;
    }

    private static void rejectUnknown(Map<String, String> query, Set<String> allowed) {
        for (String field : query.keySet()) {
            if (!allowed.contains(field)) {
                throw new FormulaResultApi.ApiProblem(
                        400,
                        "INVALID_FORMULA_RESULT_QUERY",
                        "Unknown Formula result query parameter: " + field
                );
            }
        }
    }

    private static String required(Map<String, String> query, String field) {
        String value = query.get(field);
        if (value == null || value.isBlank()) {
            throw new FormulaResultApi.ApiProblem(
                    400,
                    "INVALID_FORMULA_RESULT_QUERY",
                    field + " is required"
            );
        }
        return value.trim();
    }

    private static void send(HttpExchange exchange, FormulaResultApi.Response response)
            throws IOException {
        response.headers().forEach(exchange.getResponseHeaders()::set);
        byte[] bytes = JsonOutput.pretty(response.body()).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(response.status(), bytes.length);
        exchange.getResponseBody().write(bytes);
    }
}
