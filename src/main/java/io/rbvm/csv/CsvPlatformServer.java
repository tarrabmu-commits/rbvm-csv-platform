package io.rbvm.csv;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import io.rbvm.domain.CaseActionCommand;
import io.rbvm.domain.CaseActionType;
import io.rbvm.domain.CaseNotFoundException;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.CaseStatus;
import io.rbvm.domain.DomainCatalog;
import io.rbvm.domain.CaseWorkflowConflictException;
import io.rbvm.domain.InvalidCaseActionException;
import io.rbvm.domain.StaleCaseCursorException;
import io.rbvm.postgres.CanonicalProjectionFactory;
import io.rbvm.postgres.CanonicalProjectionFactory.RuntimeComponents;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;
import io.rbvm.security.RequestRateLimiter;
import io.rbvm.security.RequestRateLimiter.Decision;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Dependency-free HTTP adapter and local browser entry point. */
public final class CsvPlatformServer implements AutoCloseable {
    private static final Pattern IMPORT_PATH = Pattern.compile(
            "^/api/v1/csv-imports/([0-9a-fA-F-]{36})(/confirm)?$");
    private static final Pattern CASE_PATH = Pattern.compile(
            "^/api/v1/cases/([a-f0-9]{64})(/actions)?$");
    private static final long DEFAULT_MAXIMUM_UPLOAD_BYTES = 100L * 1024L * 1024L;
    private static final int MAXIMUM_ACTION_BODY_BYTES = 16 * 1024;

    private final HttpServer server;
    private final ExecutorService executor;
    private final CsvImportService imports;
    private final byte[] webUi;
    private final ApiKeyAuthenticator authenticator;
    private final RequestRateLimiter rateLimiter;
    private final Instant startedAt = Instant.now();
    private final AtomicLong requestsTotal = new AtomicLong();
    private final AtomicLong problemsTotal = new AtomicLong();
    private final AtomicLong authenticationFailuresTotal = new AtomicLong();
    private final AtomicLong forbiddenTotal = new AtomicLong();
    private final AtomicLong rateLimitedTotal = new AtomicLong();

    public CsvPlatformServer(String host, int port, Path dataDirectory, long maximumUploadBytes)
            throws IOException {
        this(
                host,
                port,
                dataDirectory,
                maximumUploadBytes,
                new NoopCanonicalProjection()
        );
    }

    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection
    ) throws IOException {
        if (port < 0 || port > 65_535) {
            throw new IllegalArgumentException("port must be between 0 and 65535");
        }
        this.imports = new CsvImportService(
                dataDirectory,
                maximumUploadBytes,
                canonicalProjection
        );
        this.authenticator = ApiKeyAuthenticator.disabled();
        this.rateLimiter = RequestRateLimiter.disabled();
        this.webUi = loadResource("/web/index.html");
        this.server = HttpServer.create(new InetSocketAddress(host, port), 32);
        int workers = Math.max(4, Math.min(16, Runtime.getRuntime().availableProcessors()));
        this.executor = Executors.newFixedThreadPool(workers);
        this.server.setExecutor(executor);
        this.server.createContext("/", this::route);
    }

    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog
    ) throws IOException {
        this(host, port, dataDirectory, maximumUploadBytes, canonicalProjection, readCatalog,
                ApiKeyAuthenticator.disabled(), RequestRateLimiter.disabled());
    }

    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog,
            ApiKeyAuthenticator authenticator
    ) throws IOException {
        this(host, port, dataDirectory, maximumUploadBytes, canonicalProjection, readCatalog,
                authenticator, RequestRateLimiter.disabled());
    }

    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog,
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        if (port < 0 || port > 65_535) {
            throw new IllegalArgumentException("port must be between 0 and 65535");
        }
        DomainCatalog mutationCatalog = "POSTGRESQL".equals(readCatalog.backend())
                ? new io.rbvm.domain.InMemoryDomainCatalog()
                : readCatalog;
        this.imports = new CsvImportService(
                dataDirectory,
                maximumUploadBytes,
                java.time.Clock.systemUTC(),
                mutationCatalog,
                readCatalog,
                canonicalProjection
        );
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter");
        this.webUi = loadResource("/web/index.html");
        this.server = HttpServer.create(new InetSocketAddress(host, port), 32);
        int workers = Math.max(4, Math.min(16, Runtime.getRuntime().availableProcessors()));
        this.executor = Executors.newFixedThreadPool(workers);
        this.server.setExecutor(executor);
        this.server.createContext("/", this::route);
    }

    public void start() {
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public URI baseUri() {
        String host = server.getAddress().getHostString();
        return URI.create("http://" + host + ':' + port() + '/');
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
        imports.close();
    }

    private void route(HttpExchange exchange) throws IOException {
        requestsTotal.incrementAndGet();
        String correlationId = UUID.randomUUID().toString();
        try {
            addCommonHeaders(exchange.getResponseHeaders(), correlationId);
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);

            if ("/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", webUi);
                return;
            }
            if ("/api/v1/health".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                sendJson(exchange, 200, imports.health());
                return;
            }
            if ("/api/v1/live".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendJson(exchange, 200, Map.of("status", "UP", "startedAt", startedAt.toString()));
                return;
            }
            if ("/api/v1/ready".equals(path)) {
                requireMethod(exchange, method, "GET");
                Map<String, Object> readiness = imports.health();
                int status = "UP".equals(readiness.get("status")) ? 200 : 503;
                sendJson(exchange, status, Map.of(
                        "status", readiness.get("status"),
                        "checkedAt", Instant.now().toString()
                ));
                return;
            }
            if ("/api/v1/metrics".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                sendMetrics(exchange);
                return;
            }
            if ("/api/v1/catalog/summary".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                sendJson(exchange, 200, imports.catalogSummary());
                return;
            }
            if ("/api/v1/cases".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                sendJson(exchange, 200, imports.queryCases(parseCaseQuery(exchange.getRequestURI())));
                return;
            }
            if ("/api/v1/csv-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createImport(exchange);
                return;
            }

            Matcher matcher = IMPORT_PATH.matcher(path);
            if (matcher.matches()) {
                UUID importId;
                try {
                    importId = UUID.fromString(matcher.group(1));
                } catch (IllegalArgumentException exception) {
                    throw new HttpProblem(400, "INVALID_IMPORT_ID", "Invalid import identifier");
                }
                if (matcher.group(2) == null) {
                    requireMethod(exchange, method, "GET");
                    authorize(exchange, ApiRole.VIEWER);
                    getImport(exchange, importId);
                } else {
                    requireMethod(exchange, method, "POST");
                    authorize(exchange, ApiRole.OPERATOR);
                    confirmImport(exchange, importId);
                }
                return;
            }

            Matcher caseMatcher = CASE_PATH.matcher(path);
            if (caseMatcher.matches()) {
                String caseId = caseMatcher.group(1);
                if (caseMatcher.group(2) == null) {
                    requireMethod(exchange, method, "GET");
                    authorize(exchange, ApiRole.VIEWER);
                    getCase(exchange, caseId);
                } else {
                    requireMethod(exchange, method, "POST");
                    AuthPrincipal principal = authorize(exchange, ApiRole.OPERATOR);
                    actOnCase(exchange, caseId, principal);
                }
                return;
            }

            throw new HttpProblem(404, "NOT_FOUND", "The requested route does not exist");
        } catch (HttpProblem problem) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, problem.status(), problem.code(), problem.getMessage(), correlationId);
        } catch (CsvImportService.UploadTooLargeException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 413, "UPLOAD_TOO_LARGE", exception.getMessage(), correlationId);
        } catch (CsvImportService.IdempotencyConflictException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 409, "IDEMPOTENCY_CONFLICT", exception.getMessage(), correlationId);
        } catch (CsvImportService.InvalidImportStateException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 409, "INVALID_IMPORT_STATE", exception.getMessage(), correlationId);
        } catch (CsvImportService.ImportNotFoundException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 404, "IMPORT_NOT_FOUND", exception.getMessage(), correlationId);
        } catch (CsvImportService.InvalidRequestException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 400, "INVALID_REQUEST", exception.getMessage(), correlationId);
        } catch (CaseNotFoundException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 404, "CASE_NOT_FOUND", exception.getMessage(), correlationId);
        } catch (InvalidCaseActionException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 400, "INVALID_CASE_REQUEST", exception.getMessage(), correlationId);
        } catch (StaleCaseCursorException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 409, "STALE_CASE_CURSOR", exception.getMessage(), correlationId);
        } catch (CaseWorkflowConflictException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 409, "CASE_WORKFLOW_CONFLICT", exception.getMessage(), correlationId);
        } catch (CsvContractException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 422, "CSV_CONTRACT_REJECTED", exception.getMessage(), correlationId);
        } catch (Exception exception) {
            problemsTotal.incrementAndGet();
            exception.printStackTrace(System.err);
            sendProblem(exchange, 500, "INTERNAL_ERROR", "The request could not be completed", correlationId);
        } finally {
            exchange.close();
        }
    }

    private void createImport(HttpExchange exchange) throws IOException {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isCsvContentType(contentType)) {
            throw new HttpProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be text/csv, application/csv, or application/octet-stream"
            );
        }
        String sourceProfile = exchange.getRequestHeaders().getFirst("X-Source-Profile-Id");
        String contractId = exchange.getRequestHeaders().getFirst("X-CSV-Contract");
        String idempotencyKey = exchange.getRequestHeaders().getFirst("Idempotency-Key");
        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));

        CsvImportService.CreateResult result;
        try (InputStream body = exchange.getRequestBody()) {
            result = imports.create(body, contentLength, sourceProfile, idempotencyKey, contractId);
        }
        if (result.replayed()) {
            exchange.getResponseHeaders().set("Idempotency-Replayed", "true");
            if (result.replayReason() != null) {
                exchange.getResponseHeaders().set("RBVM-Replay-Reason", result.replayReason());
            }
        } else {
            exchange.getResponseHeaders().set(
                    "Location",
                    "/api/v1/csv-imports/" + result.importView().get("importId")
            );
        }
        sendJson(exchange, result.replayed() ? 200 : 201, result.importView());
    }

    private void getImport(HttpExchange exchange, UUID importId) throws IOException {
        Map<String, Object> view = imports.find(importId)
                .orElseThrow(() -> new CsvImportService.ImportNotFoundException(importId));
        sendJson(exchange, 200, view);
    }

    private void confirmImport(HttpExchange exchange, UUID importId) throws IOException {
        validateIdempotencyHeader(exchange.getRequestHeaders().getFirst("Idempotency-Key"));
        CsvImportService.ConfirmResult result = imports.confirm(importId);
        if (result.replayed()) {
            exchange.getResponseHeaders().set("Idempotency-Replayed", "true");
        }
        sendJson(exchange, 200, result.importView());
    }

    private void getCase(HttpExchange exchange, String caseId) throws IOException {
        Map<String, Object> view = imports.caseDetail(caseId)
                .orElseThrow(() -> new CaseNotFoundException(caseId));
        sendJson(exchange, 200, view);
    }

    private void actOnCase(HttpExchange exchange, String caseId, AuthPrincipal principal)
            throws IOException {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.split(";", 2)[0].trim()
                .equalsIgnoreCase("application/x-www-form-urlencoded")) {
            throw new HttpProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Case actions require application/x-www-form-urlencoded"
            );
        }
        String idempotencyKey = exchange.getRequestHeaders().getFirst("Idempotency-Key");
        validateIdempotencyHeader(idempotencyKey);
        Map<String, String> form;
        try (InputStream body = exchange.getRequestBody()) {
            form = readForm(body);
        }
        rejectUnknownFields(form, Set.of("action", "reason", "expiresAt", "evidenceReference"));

        CaseActionType action;
        try {
            action = CaseActionType.valueOf(requiredForm(form, "action").toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new InvalidCaseActionException("action is not recognized");
        }
        Instant expiresAt = parseOptionalInstant(form.get("expiresAt"));
        CaseActionCommand command = new CaseActionCommand(
                action,
                form.get("reason"),
                expiresAt,
                form.get("evidenceReference")
        );
        CsvImportService.CaseActionResult result = imports.actOnCase(
                caseId,
                command,
                idempotencyKey,
                principal.actorId(),
                principal.assurance()
        );
        if (result.replayed()) {
            exchange.getResponseHeaders().set("Idempotency-Replayed", "true");
        }
        sendJson(exchange, 200, result.toMap());
    }

    private static void validateIdempotencyHeader(String key) {
        if (key == null || key.isBlank() || key.trim().length() < 8 || key.trim().length() > 128) {
            throw new CsvImportService.InvalidRequestException(
                    "Idempotency-Key must contain between 8 and 128 characters");
        }
    }

    private static boolean isCsvContentType(String value) {
        if (value == null) {
            return false;
        }
        String mediaType = value.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        return mediaType.equals("text/csv")
                || mediaType.equals("application/csv")
                || mediaType.equals("application/octet-stream");
    }

    private static long parseContentLength(String value) {
        if (value == null || value.isBlank()) {
            return -1;
        }
        try {
            long length = Long.parseLong(value);
            if (length < 0) {
                throw new NumberFormatException("negative");
            }
            return length;
        } catch (NumberFormatException exception) {
            throw new HttpProblem(400, "INVALID_CONTENT_LENGTH", "Content-Length is invalid");
        }
    }

    private static CaseQuery parseCaseQuery(URI uri) {
        Map<String, String> query = parseParameters(uri.getRawQuery());
        rejectUnknownFields(query, Set.of("limit", "cursor", "severity", "status", "cve", "asset"));
        int limit = 20;
        if (query.containsKey("limit")) {
            try {
                limit = Integer.parseInt(query.get("limit"));
                if (limit < 0 || limit > 100) {
                    throw new NumberFormatException("out of range");
                }
            } catch (NumberFormatException exception) {
                throw new InvalidCaseActionException("limit must be between 0 and 100");
            }
        }
        return new CaseQuery(
                limit,
                query.get("cursor"),
                parseEnumSet(query.get("severity"), CsvSeverity.class, "severity"),
                parseEnumSet(query.get("status"), CaseStatus.class, "status"),
                query.get("cve"),
                query.get("asset")
        );
    }

    private static Map<String, String> readForm(InputStream input) throws IOException {
        byte[] bytes = input.readNBytes(MAXIMUM_ACTION_BODY_BYTES + 1);
        if (bytes.length > MAXIMUM_ACTION_BODY_BYTES) {
            throw new HttpProblem(413, "ACTION_BODY_TOO_LARGE", "Case action body exceeds 16 KiB");
        }
        return parseParameters(new String(bytes, StandardCharsets.UTF_8));
    }

    private static Map<String, String> parseParameters(String encoded) {
        Map<String, String> output = new LinkedHashMap<>();
        if (encoded == null || encoded.isBlank()) {
            return output;
        }
        for (String parameter : encoded.split("&")) {
            String[] pair = parameter.split("=", 2);
            String name;
            String value;
            try {
                name = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                value = URLDecoder.decode(pair.length == 2 ? pair[1] : "", StandardCharsets.UTF_8);
            } catch (IllegalArgumentException exception) {
                throw new InvalidCaseActionException("Request parameters contain invalid encoding");
            }
            if (name.isBlank()) {
                throw new InvalidCaseActionException("Request parameter name cannot be empty");
            }
            if (output.putIfAbsent(name, value) != null) {
                throw new InvalidCaseActionException("Duplicate request parameter: " + name);
            }
        }
        return output;
    }

    private static <E extends Enum<E>> Set<E> parseEnumSet(
            String value,
            Class<E> type,
            String field
    ) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        Set<E> output = EnumSet.noneOf(type);
        for (String token : value.split(",")) {
            try {
                output.add(Enum.valueOf(type, token.trim().toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException exception) {
                throw new InvalidCaseActionException(field + " contains an unknown value: " + token);
            }
        }
        return output;
    }

    private static void rejectUnknownFields(Map<String, String> values, Set<String> allowed) {
        Set<String> unknown = new HashSet<>(values.keySet());
        unknown.removeAll(allowed);
        if (!unknown.isEmpty()) {
            throw new InvalidCaseActionException("Unknown request fields: " + unknown);
        }
    }

    private static String requiredForm(Map<String, String> form, String field) {
        String value = form.get(field);
        if (value == null || value.isBlank()) {
            throw new InvalidCaseActionException(field + " is required");
        }
        return value.trim();
    }

    private static Instant parseOptionalInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value.trim());
        } catch (DateTimeParseException exception) {
            throw new InvalidCaseActionException("expiresAt must be ISO-8601 with timezone");
        }
    }

    private static void requireMethod(HttpExchange exchange, String actual, String expected) {
        if (!expected.equals(actual)) {
            exchange.getResponseHeaders().set("Allow", expected);
            throw new HttpProblem(405, "METHOD_NOT_ALLOWED", "Use " + expected + " for this route");
        }
    }

    private AuthPrincipal authorize(HttpExchange exchange, ApiRole required) {
        java.util.List<String> authorization = exchange.getRequestHeaders().get("Authorization");
        String authorizationHeader = authorization == null || authorization.size() != 1
                ? null
                : authorization.get(0);
        AuthPrincipal principal = authenticator.authenticate(authorizationHeader)
                .orElseThrow(() -> {
                    Decision decision = rateLimiter.checkAuthenticationFailure(
                            exchange.getRemoteAddress().getAddress().getHostAddress());
                    if (!decision.permitted()) {
                        rejectRateLimit(exchange, decision);
                    }
                    authenticationFailuresTotal.incrementAndGet();
                    exchange.getResponseHeaders().set(
                            "WWW-Authenticate", "Bearer realm=\"rbvm-api\"");
                    return new HttpProblem(401, "AUTHENTICATION_REQUIRED",
                            "A valid bearer API key is required");
                });
        Decision decision = rateLimiter.checkActor(principal.actorId());
        if (!decision.permitted()) {
            rejectRateLimit(exchange, decision);
        }
        if (!principal.role().permits(required)) {
            forbiddenTotal.incrementAndGet();
            throw new HttpProblem(403, "INSUFFICIENT_ROLE",
                    "The authenticated identity is not permitted to perform this operation");
        }
        return principal;
    }

    private void rejectRateLimit(HttpExchange exchange, Decision decision) {
        rateLimitedTotal.incrementAndGet();
        exchange.getResponseHeaders().set(
                "Retry-After", Integer.toString(decision.retryAfterSeconds()));
        throw new HttpProblem(429, "RATE_LIMIT_EXCEEDED",
                "Request rate limit exceeded; retry after the indicated interval");
    }

    private static void sendProblem(
            HttpExchange exchange,
            int status,
            String code,
            String detail,
            String correlationId
    ) throws IOException {
        Map<String, Object> problem = new LinkedHashMap<>();
        problem.put("type", "urn:rbvm:problem:" + code.toLowerCase(Locale.ROOT));
        problem.put("title", code.replace('_', ' '));
        problem.put("status", status);
        problem.put("detail", detail);
        problem.put("correlationId", correlationId);
        sendBytes(
                exchange,
                status,
                "application/problem+json; charset=utf-8",
                JsonOutput.pretty(problem).getBytes(StandardCharsets.UTF_8)
        );
    }

    private static void sendJson(HttpExchange exchange, int status, Map<String, Object> value)
            throws IOException {
        sendBytes(
                exchange,
                status,
                "application/json; charset=utf-8",
                JsonOutput.pretty(value).getBytes(StandardCharsets.UTF_8)
        );
    }

    private void sendMetrics(HttpExchange exchange) throws IOException {
        Map<String, Object> health = imports.health();
        long uptime = Math.max(0, java.time.Duration.between(startedAt, Instant.now()).toSeconds());
        String metrics = "# TYPE rbvm_up gauge\n"
                + "rbvm_up " + ("UP".equals(health.get("status")) ? 1 : 0) + "\n"
                + "# TYPE rbvm_http_requests_total counter\n"
                + "rbvm_http_requests_total " + requestsTotal.get() + "\n"
                + "# TYPE rbvm_http_problems_total counter\n"
                + "rbvm_http_problems_total " + problemsTotal.get() + "\n"
                + "# TYPE rbvm_authentication_failures_total counter\n"
                + "rbvm_authentication_failures_total " + authenticationFailuresTotal.get() + "\n"
                + "# TYPE rbvm_authorization_forbidden_total counter\n"
                + "rbvm_authorization_forbidden_total " + forbiddenTotal.get() + "\n"
                + "# TYPE rbvm_rate_limited_total counter\n"
                + "rbvm_rate_limited_total " + rateLimitedTotal.get() + "\n"
                + "# TYPE rbvm_process_uptime_seconds gauge\n"
                + "rbvm_process_uptime_seconds " + uptime + "\n"
                + "# TYPE rbvm_imports_stored gauge\n"
                + "rbvm_imports_stored " + health.get("storedImports") + "\n"
                + "# TYPE rbvm_cases gauge\n"
                + "rbvm_cases " + health.get("cases") + "\n";
        sendBytes(exchange, 200, "text/plain; version=0.0.4; charset=utf-8",
                metrics.getBytes(StandardCharsets.UTF_8));
    }

    private static void sendBytes(HttpExchange exchange, int status, String contentType, byte[] body)
            throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private static void addCommonHeaders(Headers headers, String correlationId) {
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'");
        headers.set("X-Correlation-Id", correlationId);
    }

    private static byte[] loadResource(String name) throws IOException {
        try (InputStream input = CsvPlatformServer.class.getResourceAsStream(name)) {
            if (input == null) {
                throw new IOException("Required server resource is missing: " + name);
            }
            return input.readAllBytes();
        }
    }

    public static void main(String[] args) throws Exception {
        ServerConfiguration configuration = ServerConfiguration.fromEnvironment();
        RuntimeComponents runtime = CanonicalProjectionFactory.runtimeFromEnvironment(System.getenv());
        ApiKeyAuthenticator authenticator = ApiKeyAuthenticator.fromEnvironment(System.getenv());
        RequestRateLimiter rateLimiter = RequestRateLimiter.fromEnvironment(System.getenv());
        CanonicalProjection canonicalProjection = runtime.canonicalProjection();
        CsvPlatformServer application = new CsvPlatformServer(
                configuration.host(),
                configuration.port(),
                configuration.dataDirectory(),
                configuration.maximumUploadBytes(),
                canonicalProjection,
                runtime.readCatalog(),
                authenticator,
                rateLimiter
        );
        Runtime.getRuntime().addShutdownHook(new Thread(application::close, "rbvm-shutdown"));
        application.start();
        System.out.println("RBVM CSV Platform is running at " + application.baseUri());
        System.out.println("Data directory: " + configuration.dataDirectory().toAbsolutePath().normalize());
        System.out.println("Canonical projection: "
                + canonicalProjection.health().get("backend"));
        System.out.println("API authentication: "
                + (authenticator.enabled() ? "API_KEY" : "DISABLED"));
        new CountDownLatch(1).await();
    }

    private record ServerConfiguration(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes
    ) {
        private static ServerConfiguration fromEnvironment() {
            String host = environment("RBVM_HOST", "127.0.0.1");
            int port = parseInteger(environment("RBVM_PORT", "8080"), "RBVM_PORT", 1, 65_535);
            Path data = Path.of(environment("RBVM_DATA_DIR", "data"));
            long max = parseLong(
                    environment("RBVM_MAX_UPLOAD_BYTES", Long.toString(DEFAULT_MAXIMUM_UPLOAD_BYTES)),
                    "RBVM_MAX_UPLOAD_BYTES",
                    1,
                    Long.MAX_VALUE
            );
            return new ServerConfiguration(host, port, data, max);
        }

        private static String environment(String name, String fallback) {
            String value = System.getenv(name);
            return value == null || value.isBlank() ? fallback : value.trim();
        }

        private static int parseInteger(String value, String name, int minimum, int maximum) {
            long parsed = parseLong(value, name, minimum, maximum);
            return Math.toIntExact(parsed);
        }

        private static long parseLong(String value, String name, long minimum, long maximum) {
            try {
                long parsed = Long.parseLong(value);
                if (parsed < minimum || parsed > maximum) {
                    throw new IllegalArgumentException(
                            name + " must be between " + minimum + " and " + maximum);
                }
                return parsed;
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException(name + " must be an integer", exception);
            }
        }
    }

    private static final class HttpProblem extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final int status;
        private final String code;

        private HttpProblem(int status, String code, String message) {
            super(Objects.requireNonNull(message, "message"));
            this.status = status;
            this.code = Objects.requireNonNull(code, "code");
        }

        private int status() {
            return status;
        }

        private String code() {
            return code;
        }
    }
}
