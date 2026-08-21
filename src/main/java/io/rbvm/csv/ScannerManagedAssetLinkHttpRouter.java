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

/** Narrow socket-routing adapter for SCANNER_MANAGED_ASSET_LINK_API_V1. */
final class ScannerManagedAssetLinkHttpRouter {
    private static final String COLLECTION_PATH = "/api/v1/scanner-assets";
    private static final Pattern LINK_PATH = Pattern.compile(
            "^/api/v1/scanner-assets/([0-9a-fA-F-]{36})/managed-asset-link(/revisions)?$");

    private final ScannerManagedAssetLinkApi api;

    ScannerManagedAssetLinkHttpRouter(ScannerManagedAssetLinkApi api) {
        this.api = Objects.requireNonNull(api, "api");
    }

    static boolean inNamespace(String path) {
        return COLLECTION_PATH.equals(path) || path.startsWith(COLLECTION_PATH + '/');
    }

    static boolean handles(String path) {
        return COLLECTION_PATH.equals(path) || LINK_PATH.matcher(path).matches();
    }

    static ApiRole requiredRole(HttpExchange exchange, String method) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        String path = exchange.getRequestURI().getPath();
        if (COLLECTION_PATH.equals(path)) {
            if ("GET".equals(method)) return ApiRole.VIEWER;
            rejectMethod(exchange, "GET", "Use GET for this route");
        }
        Matcher matcher = LINK_PATH.matcher(path);
        if (!matcher.matches()) {
            throw new ManagedAssetApi.ApiProblem(
                    404,
                    "NOT_FOUND",
                    "The requested scanner-managed-asset link route does not exist"
            );
        }
        if (matcher.group(2) == null) {
            if ("GET".equals(method)) return ApiRole.VIEWER;
            rejectMethod(exchange, "GET", "Use GET for this route");
        }
        if ("GET".equals(method)) return ApiRole.VIEWER;
        if ("POST".equals(method)) return ApiRole.OPERATOR;
        rejectMethod(exchange, "GET, POST", "Use GET or POST for this route");
        throw new IllegalStateException("unreachable scanner-managed-asset link method resolution");
    }

    void routeAuthorized(HttpExchange exchange, String method, AuthPrincipal principal)
            throws IOException {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(principal, "principal");
        String path = exchange.getRequestURI().getPath();
        if (COLLECTION_PATH.equals(path)) {
            requireMethod(exchange, method, "GET");
            send(exchange, api.list(exchange.getRequestURI()));
            return;
        }
        Matcher matcher = LINK_PATH.matcher(path);
        if (!matcher.matches()) {
            throw new ManagedAssetApi.ApiProblem(
                    404,
                    "NOT_FOUND",
                    "The requested scanner-managed-asset link route does not exist"
            );
        }
        UUID scannerAssetId = parseScannerAssetId(matcher.group(1));
        if (matcher.group(2) == null) {
            requireMethod(exchange, method, "GET");
            requireNoQuery(exchange);
            send(exchange, api.current(scannerAssetId));
            return;
        }
        if ("GET".equals(method)) {
            send(exchange, api.history(scannerAssetId, exchange.getRequestURI()));
            return;
        }
        if ("POST".equals(method)) {
            requireNoQuery(exchange);
            send(exchange, api.revise(
                    scannerAssetId,
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
                    "INVALID_SCANNER_ASSET_QUERY",
                    "This scanner-managed-asset link route does not accept query parameters"
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
        if (values == null || values.isEmpty()) return null;
        if (values.size() != 1) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_REQUEST_HEADERS",
                    name + " must occur at most once"
            );
        }
        return values.get(0);
    }

    private static UUID parseScannerAssetId(String value) {
        try {
            UUID parsed = UUID.fromString(value);
            if (!parsed.toString().equalsIgnoreCase(value)) {
                throw new IllegalArgumentException("non-canonical UUID");
            }
            return parsed;
        } catch (IllegalArgumentException exception) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_SCANNER_ASSET_ID",
                    "scannerAssetId must be a canonical UUID"
            );
        }
    }

    private static void send(HttpExchange exchange, ScannerManagedAssetLinkApi.Response response)
            throws IOException {
        response.headers().forEach(exchange.getResponseHeaders()::set);
        byte[] bytes = JsonOutput.pretty(response.body()).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(response.status(), bytes.length);
        exchange.getResponseBody().write(bytes);
    }
}
