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

/** Exact HTTP transport for derived-risk methodology discovery, reads, and materialization. */
final class DerivedRiskResultHttpRouter {
    private static final String METHODOLOGY_CATALOG_PATH = "/api/v1/derived-risk-methodologies";
    private static final String RESULT_COLLECTION_PATH = "/api/v1/derived-risk-results";
    private static final Pattern RESULT_ITEM_PATH = Pattern.compile(
            "^/api/v1/derived-risk-results/([^/]+)$"
    );
    private static final String MATERIALIZATION_COLLECTION_PATH =
            "/api/v1/derived-risk-result-materializations";
    private static final Pattern MATERIALIZATION_ITEM_PATH = Pattern.compile(
            "^/api/v1/derived-risk-result-materializations/([^/]+)/([^/]+)/([^/]+)$"
    );

    private final DerivedRiskResultApi api;

    DerivedRiskResultHttpRouter(DerivedRiskResultApi api) {
        this.api = Objects.requireNonNull(api, "api");
    }

    static boolean inNamespace(String path) {
        return METHODOLOGY_CATALOG_PATH.equals(path)
                || path.startsWith(METHODOLOGY_CATALOG_PATH + '/')
                || RESULT_COLLECTION_PATH.equals(path)
                || path.startsWith(RESULT_COLLECTION_PATH + '/')
                || MATERIALIZATION_COLLECTION_PATH.equals(path)
                || path.startsWith(MATERIALIZATION_COLLECTION_PATH + '/');
    }

    static boolean handles(String path) {
        return METHODOLOGY_CATALOG_PATH.equals(path)
                || RESULT_COLLECTION_PATH.equals(path)
                || RESULT_ITEM_PATH.matcher(path).matches()
                || MATERIALIZATION_ITEM_PATH.matcher(path).matches();
    }

    /** Resolve route-specific RBAC before capability lookup so V24 availability is not leaked. */
    static ApiRole requiredRole(HttpExchange exchange, String method) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        String path = exchange.getRequestURI().getPath();

        if (MATERIALIZATION_ITEM_PATH.matcher(path).matches()) {
            if (!"POST".equals(method)) {
                exchange.getResponseHeaders().set("Allow", "POST");
                throw new DerivedRiskResultApi.ApiProblem(
                        405,
                        "METHOD_NOT_ALLOWED",
                        "Use POST for this route"
                );
            }
            return ApiRole.OPERATOR;
        }

        if (!"GET".equals(method)) {
            exchange.getResponseHeaders().set("Allow", "GET");
            throw new DerivedRiskResultApi.ApiProblem(
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

        if (METHODOLOGY_CATALOG_PATH.equals(path)) {
            if (!"GET".equals(method)) {
                requiredRole(exchange, method);
            }
            rejectQuery(exchange, "Derived risk methodology catalog does not accept query parameters");
            send(exchange, api.listMethodologies());
            return;
        }

        Matcher materialization = MATERIALIZATION_ITEM_PATH.matcher(path);
        if (materialization.matches()) {
            if (!"POST".equals(method)) {
                requiredRole(exchange, method);
            }
            rejectQuery(exchange, "Derived risk materialization does not accept query parameters");
            if (exchange.getRequestBody().read() != -1) {
                throw new DerivedRiskResultApi.ApiProblem(
                        400,
                        "DERIVED_RISK_MATERIALIZATION_BODY_NOT_ALLOWED",
                        "Derived risk materialization accepts exact identities in the path only"
                );
            }
            send(exchange, api.materialize(
                    materialization.group(1),
                    materialization.group(2),
                    materialization.group(3)
            ));
            return;
        }

        if (!"GET".equals(method)) {
            requiredRole(exchange, method);
        }

        if (RESULT_COLLECTION_PATH.equals(path)) {
            Map<String, String> query = parseParameters(exchange.getRequestURI().getRawQuery());
            rejectUnknown(query, Set.of(
                    "inputSnapshotSha256",
                    "methodologyId",
                    "methodologySha256"
            ));
            String snapshotSha = required(query, "inputSnapshotSha256");
            String methodologyId = required(query, "methodologyId");
            String methodologySha = required(query, "methodologySha256");
            send(exchange, api.getByInputSnapshotAndMethodology(
                    snapshotSha,
                    methodologyId,
                    methodologySha
            ));
            return;
        }

        Matcher item = RESULT_ITEM_PATH.matcher(path);
        if (!item.matches()) {
            throw new DerivedRiskResultApi.ApiProblem(
                    404,
                    "NOT_FOUND",
                    "The requested derived risk result route does not exist"
            );
        }
        rejectQuery(exchange, "Exact derived risk result lookup does not accept query parameters");
        send(exchange, api.getByResultSha256(item.group(1)));
    }

    private static void rejectQuery(HttpExchange exchange, String detail) {
        String rawQuery = exchange.getRequestURI().getRawQuery();
        if (rawQuery != null && !rawQuery.isBlank()) {
            throw new DerivedRiskResultApi.ApiProblem(
                    400,
                    "INVALID_DERIVED_RISK_RESULT_QUERY",
                    detail
            );
        }
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
                throw new DerivedRiskResultApi.ApiProblem(
                        400,
                        "INVALID_DERIVED_RISK_RESULT_QUERY",
                        "Derived risk result query parameters contain invalid encoding"
                );
            }
            if (name.isBlank()) {
                throw new DerivedRiskResultApi.ApiProblem(
                        400,
                        "INVALID_DERIVED_RISK_RESULT_QUERY",
                        "Derived risk result query parameter name cannot be empty"
                );
            }
            if (output.putIfAbsent(name, value) != null) {
                throw new DerivedRiskResultApi.ApiProblem(
                        400,
                        "INVALID_DERIVED_RISK_RESULT_QUERY",
                        "Duplicate derived risk result query parameter: " + name
                );
            }
        }
        return output;
    }

    private static void rejectUnknown(Map<String, String> query, Set<String> allowed) {
        for (String field : query.keySet()) {
            if (!allowed.contains(field)) {
                throw new DerivedRiskResultApi.ApiProblem(
                        400,
                        "INVALID_DERIVED_RISK_RESULT_QUERY",
                        "Unknown derived risk result query parameter: " + field
                );
            }
        }
    }

    private static String required(Map<String, String> query, String field) {
        String value = query.get(field);
        if (value == null || value.isBlank()) {
            throw new DerivedRiskResultApi.ApiProblem(
                    400,
                    "INVALID_DERIVED_RISK_RESULT_QUERY",
                    field + " is required"
            );
        }
        return value.trim();
    }

    private static void send(HttpExchange exchange, DerivedRiskResultApi.Response response)
            throws IOException {
        response.headers().forEach(exchange.getResponseHeaders()::set);
        byte[] bytes = JsonOutput.pretty(response.body()).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(response.status(), bytes.length);
        exchange.getResponseBody().write(bytes);
    }
}
