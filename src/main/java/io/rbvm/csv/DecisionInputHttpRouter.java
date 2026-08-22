package io.rbvm.csv;

import com.sun.net.httpserver.HttpExchange;

import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Socket router for exact Decision Input read/history/methodology/materialization contracts. */
final class DecisionInputHttpRouter {
    private static final String SNAPSHOT_COLLECTION = "/api/v1/decision-input-snapshots";
    private static final Pattern SNAPSHOT_ITEM = Pattern.compile(
            "^/api/v1/decision-input-snapshots/([^/]+)$"
    );
    private static final Pattern FINDING_HISTORY = Pattern.compile(
            "^/api/v1/findings/([0-9a-fA-F-]{36})/decision-input-snapshots$"
    );
    private static final String MATERIALIZATION = "/api/v1/decision-input-materializations";
    private static final String METHODOLOGY_COLLECTION = "/api/v1/decision-methodologies";
    private static final Pattern METHODOLOGY_ITEM = Pattern.compile(
            "^/api/v1/decision-methodologies/([1-9][0-9]*)$"
    );

    private final DecisionInputApi api;

    DecisionInputHttpRouter(DecisionInputApi api) {
        this.api = Objects.requireNonNull(api, "api");
    }

    static boolean inNamespace(String path) {
        if (path == null) return false;
        return SNAPSHOT_COLLECTION.equals(path)
                || path.startsWith(SNAPSHOT_COLLECTION + '/')
                || MATERIALIZATION.equals(path)
                || path.startsWith(MATERIALIZATION + '/')
                || METHODOLOGY_COLLECTION.equals(path)
                || path.startsWith(METHODOLOGY_COLLECTION + '/')
                || (path.startsWith("/api/v1/findings/")
                    && path.endsWith("/decision-input-snapshots"));
    }

    static boolean handles(String path) {
        return SNAPSHOT_ITEM.matcher(path).matches()
                || FINDING_HISTORY.matcher(path).matches()
                || MATERIALIZATION.equals(path)
                || METHODOLOGY_COLLECTION.equals(path)
                || METHODOLOGY_ITEM.matcher(path).matches();
    }

    /** Resolve RBAC before runtime lookup so Decision Input capability availability is not leaked. */
    static ApiRole requiredRole(HttpExchange exchange, String method) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        String path = exchange.getRequestURI().getPath();
        if (MATERIALIZATION.equals(path)) {
            if (!"POST".equals(method)) {
                rejectMethod(exchange, "POST", "Use POST for this route");
            }
            return ApiRole.OPERATOR;
        }
        if (!"GET".equals(method)) {
            rejectMethod(exchange, "GET", "Use GET for this route");
        }
        return ApiRole.VIEWER;
    }

    void routeAuthorized(HttpExchange exchange, String method, AuthPrincipal principal)
            throws IOException {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(principal, "principal");
        String path = exchange.getRequestURI().getPath();

        if (MATERIALIZATION.equals(path)) {
            requireMethod(exchange, method, "POST");
            requireNoQuery(exchange);
            send(exchange, api.materialize(
                    singleHeader(exchange, "Content-Type"),
                    exchange.getRequestBody()
            ));
            return;
        }

        requireMethod(exchange, method, "GET");
        Matcher snapshot = SNAPSHOT_ITEM.matcher(path);
        if (snapshot.matches()) {
            requireNoQuery(exchange);
            send(exchange, api.getSnapshot(snapshot.group(1)));
            return;
        }

        Matcher history = FINDING_HISTORY.matcher(path);
        if (history.matches()) {
            UUID findingId = parseFindingId(history.group(1));
            Map<String, String> query = parseParameters(exchange.getRequestURI().getRawQuery());
            rejectUnknown(
                    query,
                    Set.of("limit", "beforeEvaluatedAt", "beforeSnapshotSha256"),
                    "INVALID_DECISION_INPUT_HISTORY_QUERY"
            );
            int limit = pageLimit(query.get("limit"));
            String beforeAtText = trimToNull(query.get("beforeEvaluatedAt"));
            String beforeSha = trimToNull(query.get("beforeSnapshotSha256"));
            if ((beforeAtText == null) != (beforeSha == null)) {
                throw new DecisionInputApi.ApiProblem(
                        400,
                        "INVALID_DECISION_INPUT_HISTORY_QUERY",
                        "beforeEvaluatedAt and beforeSnapshotSha256 must be supplied together"
                );
            }
            Instant beforeAt = beforeAtText == null ? null : parseCanonicalInstant(
                    beforeAtText,
                    "beforeEvaluatedAt",
                    "INVALID_DECISION_INPUT_HISTORY_QUERY"
            );
            if (beforeSha != null) {
                DecisionInputApi.requireSha(beforeSha, "beforeSnapshotSha256");
            }
            send(exchange, api.history(findingId, limit, beforeAt, beforeSha));
            return;
        }

        if (METHODOLOGY_COLLECTION.equals(path)) {
            Map<String, String> query = parseParameters(exchange.getRequestURI().getRawQuery());
            rejectUnknown(
                    query,
                    Set.of("limit", "afterRevision"),
                    "INVALID_DECISION_METHODOLOGY_QUERY"
            );
            int limit = pageLimit(query.get("limit"));
            Integer afterRevision = optionalPositiveInteger(
                    query.get("afterRevision"),
                    "afterRevision",
                    "INVALID_DECISION_METHODOLOGY_QUERY"
            );
            send(exchange, api.methodologies(limit, afterRevision));
            return;
        }

        Matcher methodology = METHODOLOGY_ITEM.matcher(path);
        if (methodology.matches()) {
            requireNoQuery(exchange);
            int revision;
            try {
                revision = Integer.parseInt(methodology.group(1));
            } catch (NumberFormatException exception) {
                throw new DecisionInputApi.ApiProblem(
                        400,
                        "INVALID_DECISION_METHODOLOGY_IDENTITY",
                        "revision is out of range"
                );
            }
            send(exchange, api.getMethodology(revision));
            return;
        }

        throw new DecisionInputApi.ApiProblem(
                404,
                "NOT_FOUND",
                "The requested Decision Input route does not exist"
        );
    }

    private static void requireNoQuery(HttpExchange exchange) {
        String query = exchange.getRequestURI().getRawQuery();
        if (query != null && !query.isBlank()) {
            throw new DecisionInputApi.ApiProblem(
                    400,
                    "INVALID_DECISION_INPUT_QUERY",
                    "This exact-identity route does not accept query parameters"
            );
        }
    }

    private static void requireMethod(HttpExchange exchange, String actual, String expected) {
        if (!expected.equals(actual)) {
            rejectMethod(exchange, expected, "Use " + expected + " for this route");
        }
    }

    private static void rejectMethod(HttpExchange exchange, String allow, String detail) {
        exchange.getResponseHeaders().set("Allow", allow);
        throw new DecisionInputApi.ApiProblem(405, "METHOD_NOT_ALLOWED", detail);
    }

    private static String singleHeader(HttpExchange exchange, String name) {
        java.util.List<String> values = exchange.getRequestHeaders().get(name);
        if (values == null || values.isEmpty()) return null;
        if (values.size() != 1) {
            throw new DecisionInputApi.ApiProblem(
                    400,
                    "INVALID_REQUEST_HEADERS",
                    name + " must occur at most once"
            );
        }
        return values.get(0);
    }

    private static UUID parseFindingId(String value) {
        try {
            UUID parsed = UUID.fromString(value);
            if (!parsed.toString().equalsIgnoreCase(value)) {
                throw new IllegalArgumentException("non-canonical UUID");
            }
            return parsed;
        } catch (IllegalArgumentException exception) {
            throw new DecisionInputApi.ApiProblem(
                    400,
                    "INVALID_FINDING_ID",
                    "findingId must be a canonical UUID"
            );
        }
    }

    private static int pageLimit(String value) {
        String text = trimToNull(value);
        if (text == null) return 100;
        try {
            int limit = Integer.parseInt(text);
            if (limit < 1 || limit > 500) throw new NumberFormatException("out of range");
            return limit;
        } catch (NumberFormatException exception) {
            throw new DecisionInputApi.ApiProblem(
                    400,
                    "INVALID_DECISION_INPUT_QUERY",
                    "limit must be between 1 and 500"
            );
        }
    }

    private static Integer optionalPositiveInteger(String value, String field, String code) {
        String text = trimToNull(value);
        if (text == null) return null;
        try {
            int parsed = Integer.parseInt(text);
            if (parsed < 1) throw new NumberFormatException("not positive");
            return parsed;
        } catch (NumberFormatException exception) {
            throw new DecisionInputApi.ApiProblem(
                    400,
                    code,
                    field + " must be a positive integer"
            );
        }
    }

    private static Instant parseCanonicalInstant(String value, String field, String code) {
        try {
            Instant parsed = Instant.parse(value);
            if (!parsed.toString().equals(value)) {
                throw new DateTimeException("non-canonical Instant") { };
            }
            return parsed;
        } catch (DateTimeException exception) {
            throw new DecisionInputApi.ApiProblem(
                    400,
                    code,
                    field + " must be a canonical UTC Instant"
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
                value = URLDecoder.decode(
                        pair.length == 2 ? pair[1] : "",
                        StandardCharsets.UTF_8
                );
            } catch (IllegalArgumentException exception) {
                throw new DecisionInputApi.ApiProblem(
                        400,
                        "INVALID_DECISION_INPUT_QUERY",
                        "Decision Input query parameters contain invalid encoding"
                );
            }
            if (name.isBlank()) {
                throw new DecisionInputApi.ApiProblem(
                        400,
                        "INVALID_DECISION_INPUT_QUERY",
                        "Query parameter name cannot be empty"
                );
            }
            if (output.putIfAbsent(name, value) != null) {
                throw new DecisionInputApi.ApiProblem(
                        400,
                        "INVALID_DECISION_INPUT_QUERY",
                        "Duplicate query parameter: " + name
                );
            }
        }
        return output;
    }

    private static void rejectUnknown(
            Map<String, String> query,
            Set<String> allowed,
            String code
    ) {
        for (String field : query.keySet()) {
            if (!allowed.contains(field)) {
                throw new DecisionInputApi.ApiProblem(
                        400,
                        code,
                        "Unknown query parameter: " + field
                );
            }
        }
    }

    private static String trimToNull(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static void send(HttpExchange exchange, DecisionInputApi.Response response)
            throws IOException {
        response.headers().forEach(exchange.getResponseHeaders()::set);
        byte[] bytes = JsonOutput.pretty(response.body()).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(response.status(), bytes.length);
        exchange.getResponseBody().write(bytes);
    }
}
