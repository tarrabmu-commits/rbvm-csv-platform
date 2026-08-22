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

/** Narrow socket router for the two explicit Finding-context association API contracts. */
final class FindingContextAssociationHttpRouter {
    private static final Pattern PATH = Pattern.compile(
            "^/api/v1/findings/([0-9a-fA-F-]{36})/"
                    + "(reachability-links|business-service-links)(/(current|revisions))?$");

    private final FindingReachabilityScopeLinkApi reachability;
    private final FindingBusinessServiceLinkApi businessService;

    FindingContextAssociationHttpRouter(
            FindingReachabilityScopeLinkApi reachability,
            FindingBusinessServiceLinkApi businessService
    ) {
        this.reachability = Objects.requireNonNull(reachability, "reachability");
        this.businessService = Objects.requireNonNull(businessService, "businessService");
    }

    static boolean inNamespace(String path) {
        if (path == null || !path.startsWith("/api/v1/findings/")) return false;
        return path.contains("/reachability-links") || path.contains("/business-service-links");
    }

    static boolean handles(String path) {
        return PATH.matcher(path).matches();
    }

    static ApiRole requiredRole(HttpExchange exchange, String method) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        Matcher matcher = PATH.matcher(exchange.getRequestURI().getPath());
        if (!matcher.matches()) {
            throw new ManagedAssetApi.ApiProblem(
                    404,
                    "NOT_FOUND",
                    "The requested Finding-context association route does not exist"
            );
        }
        String operation = matcher.group(4);
        if (operation == null || "revisions".equals(operation)) {
            if ("GET".equals(method)) return ApiRole.VIEWER;
            rejectMethod(exchange, "GET", "Use GET for this route");
        }
        if ("GET".equals(method)) return ApiRole.VIEWER;
        if ("POST".equals(method)) return ApiRole.OPERATOR;
        rejectMethod(exchange, "GET, POST", "Use GET or POST for this route");
        throw new IllegalStateException("unreachable Finding-context association method resolution");
    }

    void routeAuthorized(HttpExchange exchange, String method, AuthPrincipal principal)
            throws IOException {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(principal, "principal");
        Matcher matcher = PATH.matcher(exchange.getRequestURI().getPath());
        if (!matcher.matches()) {
            throw new ManagedAssetApi.ApiProblem(
                    404,
                    "NOT_FOUND",
                    "The requested Finding-context association route does not exist"
            );
        }
        UUID findingId = parseFindingId(matcher.group(1));
        String family = matcher.group(2);
        String operation = matcher.group(4);

        if ("reachability-links".equals(family)) {
            routeReachability(exchange, method, principal, findingId, operation);
            return;
        }
        routeBusinessService(exchange, method, principal, findingId, operation);
    }

    private void routeReachability(
            HttpExchange exchange,
            String method,
            AuthPrincipal principal,
            UUID findingId,
            String operation
    ) throws IOException {
        if (operation == null) {
            requireMethod(exchange, method, "GET");
            send(exchange, reachability.list(findingId, exchange.getRequestURI()));
            return;
        }
        if ("revisions".equals(operation)) {
            requireMethod(exchange, method, "GET");
            send(exchange, reachability.history(findingId, exchange.getRequestURI()));
            return;
        }
        if ("GET".equals(method)) {
            send(exchange, reachability.current(findingId, exchange.getRequestURI()));
            return;
        }
        if ("POST".equals(method)) {
            requireNoQuery(exchange);
            send(exchange, reachability.revise(
                    findingId,
                    singleHeader(exchange, "Content-Type"),
                    exchange.getRequestBody(),
                    singleHeader(exchange, "If-Match"),
                    principal.actorId()
            ));
            return;
        }
        rejectMethod(exchange, "GET, POST", "Use GET or POST for this route");
    }

    private void routeBusinessService(
            HttpExchange exchange,
            String method,
            AuthPrincipal principal,
            UUID findingId,
            String operation
    ) throws IOException {
        if (operation == null) {
            requireMethod(exchange, method, "GET");
            send(exchange, businessService.list(findingId, exchange.getRequestURI()));
            return;
        }
        if ("revisions".equals(operation)) {
            requireMethod(exchange, method, "GET");
            send(exchange, businessService.history(findingId, exchange.getRequestURI()));
            return;
        }
        if ("GET".equals(method)) {
            send(exchange, businessService.current(findingId, exchange.getRequestURI()));
            return;
        }
        if ("POST".equals(method)) {
            requireNoQuery(exchange);
            send(exchange, businessService.revise(
                    findingId,
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
                    "INVALID_FINDING_CONTEXT_ASSOCIATION_QUERY",
                    "Mutation routes do not accept query parameters; the target belongs in the JSON body"
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

    private static UUID parseFindingId(String value) {
        try {
            UUID parsed = UUID.fromString(value);
            if (!parsed.toString().equalsIgnoreCase(value)) {
                throw new IllegalArgumentException("non-canonical UUID");
            }
            return parsed;
        } catch (IllegalArgumentException exception) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_FINDING_ID",
                    "findingId must be a canonical UUID"
            );
        }
    }

    private static void send(
            HttpExchange exchange,
            FindingReachabilityScopeLinkApi.Response response
    ) throws IOException {
        send(exchange, response.status(), response.headers(), response.body());
    }

    private static void send(
            HttpExchange exchange,
            FindingBusinessServiceLinkApi.Response response
    ) throws IOException {
        send(exchange, response.status(), response.headers(), response.body());
    }

    private static void send(
            HttpExchange exchange,
            int status,
            java.util.Map<String, String> headers,
            java.util.Map<String, Object> body
    ) throws IOException {
        headers.forEach(exchange.getResponseHeaders()::set);
        byte[] bytes = JsonOutput.pretty(body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
    }
}
