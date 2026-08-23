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
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Exact Formula discovery/result transport plus exact Decision Input workflow transport. */
final class FormulaResultHttpRouter {
    private static final String CATALOG_PATH = "/api/v1/formulas";
    private static final String COLLECTION_PATH = "/api/v1/formula-results";
    private static final Pattern ITEM_PATH = Pattern.compile(
            "^/api/v1/formula-results/([^/]+)$"
    );
    private static final String MATERIALIZATION_COLLECTION_PATH =
            "/api/v1/formula-result-materializations";
    private static final Pattern MATERIALIZATION_ITEM_PATH = Pattern.compile(
            "^/api/v1/formula-result-materializations/([^/]+)$"
    );

    private final FormulaCatalogApi catalog = new FormulaCatalogApi();
    private final FormulaResultApi api;
    private final Optional<DecisionInputHttpRouter> decisionInputs;

    FormulaResultHttpRouter(FormulaResultApi api) {
        this.api = Objects.requireNonNull(api, "api");
        this.decisionInputs = api.decisionInputs().map(DecisionInputHttpRouter::new);
    }

    static boolean inNamespace(String path) {
        return CATALOG_PATH.equals(path)
                || COLLECTION_PATH.equals(path)
                || path.startsWith(COLLECTION_PATH + '/')
                || MATERIALIZATION_COLLECTION_PATH.equals(path)
                || path.startsWith(MATERIALIZATION_COLLECTION_PATH + '/')
                || DecisionInputHttpRouter.inNamespace(path);
    }

    static boolean handles(String path) {
        return CATALOG_PATH.equals(path)
                || COLLECTION_PATH.equals(path)
                || ITEM_PATH.matcher(path).matches()
                || MATERIALIZATION_ITEM_PATH.matcher(path).matches()
                || DecisionInputHttpRouter.handles(path);
    }

    /** Resolve route-specific RBAC before capability lookup so V23 availability is not leaked. */
    static ApiRole requiredRole(HttpExchange exchange, String method) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        String path = exchange.getRequestURI().getPath();
        if (DecisionInputHttpRouter.inNamespace(path)) {
            try {
                return DecisionInputHttpRouter.requiredRole(exchange, method);
            } catch (DecisionInputApi.ApiProblem problem) {
                throw translate(problem);
            }
        }
        if (MATERIALIZATION_ITEM_PATH.matcher(path).matches()) {
            if (!"POST".equals(method)) {
                exchange.getResponseHeaders().set("Allow", "POST");
                throw new FormulaResultApi.ApiProblem(
                        405,
                        "METHOD_NOT_ALLOWED",
                        "Use POST for this route"
                );
            }
            return ApiRole.OPERATOR;
        }
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

        String path = exchange.getRequestURI().getPath();
        if (DecisionInputHttpRouter.inNamespace(path)) {
            try {
                DecisionInputHttpRouter router = decisionInputs.orElseThrow(() ->
                        new DecisionInputApi.ApiProblem(
                                503,
                                "DECISION_INPUT_RUNTIME_UNAVAILABLE",
                                "Decision Input workflow requires PostgreSQL schema version 23 or newer"
                        ));
                router.routeAuthorized(exchange, method, principal);
            } catch (DecisionInputApi.ApiProblem problem) {
                throw translate(problem);
            }
            return;
        }

        if (CATALOG_PATH.equals(path)) {
            if (!"GET".equals(method)) {
                requiredRole(exchange, method);
            }
            String rawQuery = exchange.getRequestURI().getRawQuery();
            if (rawQuery != null && !rawQuery.isBlank()) {
                throw new FormulaResultApi.ApiProblem(
                        400,
                        "INVALID_FORMULA_CATALOG_QUERY",
                        "Formula catalog discovery does not accept query parameters"
                );
            }
            send(exchange, catalog.listFormulas());
            return;
        }

        Matcher materialization = MATERIALIZATION_ITEM_PATH.matcher(path);
        if (materialization.matches()) {
            if (!"POST".equals(method)) {
                requiredRole(exchange, method);
            }
            String rawQuery = exchange.getRequestURI().getRawQuery();
            if (rawQuery != null && !rawQuery.isBlank()) {
                throw new FormulaResultApi.ApiProblem(
                        400,
                        "INVALID_FORMULA_MATERIALIZATION_REQUEST",
                        "Formula materialization does not accept query parameters"
                );
            }
            if (exchange.getRequestBody().read() != -1) {
                throw new FormulaResultApi.ApiProblem(
                        400,
                        "FORMULA_MATERIALIZATION_BODY_NOT_ALLOWED",
                        "Formula materialization accepts the exact Decision Input identity in the path only"
                );
            }
            send(exchange, api.materializeByInputSnapshotSha256(materialization.group(1)));
            return;
        }

        if (!"GET".equals(method)) {
            requiredRole(exchange, method);
        }
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

    private static FormulaResultApi.ApiProblem translate(DecisionInputApi.ApiProblem problem) {
        return new FormulaResultApi.ApiProblem(
                problem.status(),
                problem.code(),
                problem.getMessage()
        );
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

    private static void send(HttpExchange exchange, FormulaCatalogApi.Response response)
            throws IOException {
        response.headers().forEach(exchange.getResponseHeaders()::set);
        byte[] bytes = JsonOutput.pretty(response.body()).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(response.status(), bytes.length);
        exchange.getResponseBody().write(bytes);
    }
}
