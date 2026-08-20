package io.rbvm.csv;

import com.sun.net.httpserver.HttpExchange;

import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Narrow socket-routing adapter for MANAGED_ASSET_API_V1. */
final class ManagedAssetHttpRouter {
    private static final String COLLECTION_PATH = "/api/v1/managed-assets";
    private static final Pattern ITEM_PATH = Pattern.compile(
            "^/api/v1/managed-assets/([0-9a-fA-F-]{36})(/revisions)?$");

    private final ManagedAssetApi api;

    ManagedAssetHttpRouter(ManagedAssetApi api) {
        this.api = Objects.requireNonNull(api, "api");
    }

    static boolean inNamespace(String path) {
        return COLLECTION_PATH.equals(path) || path.startsWith(COLLECTION_PATH + '/');
    }

    static boolean handles(String path) {
        return COLLECTION_PATH.equals(path) || ITEM_PATH.matcher(path).matches();
    }

    /** Resolve method-level RBAC before capability lookup so disabled features do not leak pre-auth. */
    static ApiRole requiredRole(HttpExchange exchange, String method) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        String path = exchange.getRequestURI().getPath();
        if (COLLECTION_PATH.equals(path)) {
            if ("GET".equals(method)) return ApiRole.VIEWER;
            if ("POST".equals(method)) return ApiRole.OPERATOR;
            rejectMethod(exchange, "GET, POST", "Use GET or POST for this route");
        }
        Matcher matcher = ITEM_PATH.matcher(path);
        if (!matcher.matches()) {
            throw new ManagedAssetApi.ApiProblem(
                    404,
                    "NOT_FOUND",
                    "The requested managed asset route does not exist"
            );
        }
        if (matcher.group(2) == null) {
            if ("GET".equals(method)) return ApiRole.VIEWER;
            rejectMethod(exchange, "GET", "Use GET for this route");
        }
        if ("GET".equals(method)) return ApiRole.VIEWER;
        if ("POST".equals(method)) return ApiRole.OPERATOR;
        rejectMethod(exchange, "GET, POST", "Use GET or POST for this route");
        throw new IllegalStateException("unreachable managed asset method resolution");
    }

    void routeAuthorized(HttpExchange exchange, String method, AuthPrincipal principal)
            throws IOException {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(principal, "principal");
        String path = exchange.getRequestURI().getPath();
        if (COLLECTION_PATH.equals(path)) {
            routeCollection(exchange, method, principal);
            return;
        }
        Matcher matcher = ITEM_PATH.matcher(path);
        if (!matcher.matches()) {
            throw new ManagedAssetApi.ApiProblem(
                    404,
                    "NOT_FOUND",
                    "The requested managed asset route does not exist"
            );
        }
        UUID managedAssetId = parseManagedAssetId(matcher.group(1));
        if (matcher.group(2) == null) {
            requireMethod(exchange, method, "GET");
            requireNoQuery(exchange);
            send(exchange, api.get(managedAssetId));
            return;
        }
        routeRevisions(exchange, method, principal, managedAssetId);
    }

    private void routeCollection(
            HttpExchange exchange,
            String method,
            AuthPrincipal principal
    ) throws IOException {
        if ("GET".equals(method)) {
            send(exchange, api.list(exchange.getRequestURI()));
            return;
        }
        if ("POST".equals(method)) {
            requireNoQuery(exchange);
            send(exchange, api.create(
                    singleHeader(exchange, "Content-Type"),
                    exchange.getRequestBody(),
                    principal.actorId()
            ));
            return;
        }
        rejectMethod(exchange, "GET, POST", "Use GET or POST for this route");
    }

    private void routeRevisions(
            HttpExchange exchange,
            String method,
            AuthPrincipal principal,
            UUID managedAssetId
    ) throws IOException {
        if ("GET".equals(method)) {
            send(exchange, api.history(managedAssetId, exchange.getRequestURI()));
            return;
        }
        if ("POST".equals(method)) {
            requireNoQuery(exchange);
            send(exchange, api.revise(
                    managedAssetId,
                    singleHeader(exchange, "Content-Type"),
                    exchange.getRequestBody(),
                    singleHeader(exchange, "If-Match"),
                    principal.actorId()
            ));
            return;
        }
        rejectMethod(exchange, "GET, POST", "Use GET or POST for this route");
    }

    private static void requireNoQuery(HttpExchange exchange) {
        String query = exchange.getRequestURI().getRawQuery();
        if (query != null && !query.isBlank()) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_MANAGED_ASSET_QUERY",
                    "This managed asset route does not accept query parameters"
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
        throw new ManagedAssetApi.ApiProblem(405, "METHOD_NOT_ALLOWED", detail);
    }

    private static String singleHeader(HttpExchange exchange, String name) {
        List<String> values = exchange.getRequestHeaders().get(name);
        if (values == null || values.isEmpty()) {
            return null;
        }
        if (values.size() != 1) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_REQUEST_HEADERS",
                    name + " must occur at most once"
            );
        }
        return values.get(0);
    }

    private static UUID parseManagedAssetId(String value) {
        try {
            UUID parsed = UUID.fromString(value);
            if (!parsed.toString().equalsIgnoreCase(value)) {
                throw new IllegalArgumentException("non-canonical UUID");
            }
            return parsed;
        } catch (IllegalArgumentException exception) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_MANAGED_ASSET_ID",
                    "managedAssetId must be a canonical UUID"
            );
        }
    }

    private static void send(HttpExchange exchange, ManagedAssetApi.Response response)
            throws IOException {
        response.headers().forEach(exchange.getResponseHeaders()::set);
        byte[] bytes = JsonOutput.pretty(response.body()).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(response.status(), bytes.length);
        exchange.getResponseBody().write(bytes);
    }
}
