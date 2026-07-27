package io.rbvm.csv;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import io.rbvm.domain.CaseActionCommand;
import io.rbvm.domain.CaseActionType;
import io.rbvm.domain.CaseNotFoundException;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.CaseStatus;
import io.rbvm.domain.CaseWorkflowConflictException;
import io.rbvm.domain.InvalidCaseActionException;
import io.rbvm.domain.StaleCaseCursorException;
import io.rbvm.postgres.CanonicalProjectionFactory;

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
                sendJson(exchange, 200, imports.health());
                return;
            }
            if ("/api/v1/catalog/summary".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendJson(exchange, 200, imports.catalogSummary());
                return;
            }
            if ("/api/v1/cases".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendJson(exchange, 200, imports.queryCases(parseCaseQuery(exchange.getRequestURI())));
                return;
            }
            if ("/api/v1/csv-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
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
                    getImport(exchange, importId);
                } else {
                    requireMethod(exchange, method, "POST");
                    confirmImport(exchange, importId);
                }
                return;
            }

            Matcher caseMatcher = CASE_PATH.matcher(path);
            if (caseMatcher.matches()) {
                String caseId = caseMatcher.group(1);
                if (caseMatcher.group(2) == null) {
                    requireMethod(exchange, method, "GET");
                    getCase(exchange, caseId);
                } else {
                    requireMethod(exchange, method, "POST");
                    actOnCase(exchange, caseId);
                }
                return;
            }

            throw new HttpProblem(404, "NOT_FOUND", "The requested route does not exist");
        } catch (HttpProblem problem) {
            sendProblem(exchange, problem.status(), problem.code(), problem.getMessage(), correlationId);
        } catch (CsvImportService.UploadTooLargeException exception) {
            sendProblem(exchange, 413, "UPLOAD_TOO_LARGE", exception.getMessage(), correlationId);
        } catch (CsvImportService.IdempotencyConflictException exception) {
            sendProblem(exchange, 409, "IDEMPOTENCY_CONFLICT", exception.getMessage(), correlationId);
        } catch (CsvImportService.InvalidImportStateException exception) {
            sendProblem(exchange, 409, "INVALID_IMPORT_STATE", exception.getMessage(), correlationId);
        } catch (CsvImportService.ImportNotFoundException exception) {
            sendProblem(exchange, 404, "IMPORT_NOT_FOUND", exception.getMessage(), correlationId);
        } catch (CsvImportService.InvalidRequestException exception) {
            sendProblem(exchange, 400, "INVALID_REQUEST", exception.getMessage(), correlationId);
        } catch (CaseNotFoundException exception) {
            sendProblem(exchange, 404, "CASE_NOT_FOUND", exception.getMessage(), correlationId);
        } catch (InvalidCaseActionException exception) {
            sendProblem(exchange, 400, "INVALID_CASE_REQUEST", exception.getMessage(), correlationId);
        } catch (StaleCaseCursorException exception) {
            sendProblem(exchange, 409, "STALE_CASE_CURSOR", exception.getMessage(), correlationId);
        } catch (CaseWorkflowConflictException exception) {
            sendProblem(exchange, 409, "CASE_WORKFLOW_CONFLICT", exception.getMessage(), correlationId);
        } catch (CsvContractException exception) {
            sendProblem(exchange, 422, "CSV_CONTRACT_REJECTED", exception.getMessage(), correlationId);
        } catch (Exception exception) {
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
        String idempotencyKey = exchange.getRequestHeaders().getFirst("Idempotency-Key");
        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));

        CsvImportService.CreateResult result;
        try (InputStream body = exchange.getRequestBody()) {
            result = imports.create(body, contentLength, sourceProfile, idempotencyKey);
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

    private void actOnCase(HttpExchange exchange, String caseId) throws IOException {
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
                idempotencyKey
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
        CanonicalProjection canonicalProjection = CanonicalProjectionFactory.fromEnvironment(
                System.getenv()
        );
        CsvPlatformServer application = new CsvPlatformServer(
                configuration.host(),
                configuration.port(),
                configuration.dataDirectory(),
                configuration.maximumUploadBytes(),
                canonicalProjection
        );
        Runtime.getRuntime().addShutdownHook(new Thread(application::close, "rbvm-shutdown"));
        application.start();
        System.out.println("RBVM CSV Platform is running at " + application.baseUri());
        System.out.println("Data directory: " + configuration.dataDirectory().toAbsolutePath().normalize());
        System.out.println("Canonical projection: "
                + canonicalProjection.health().get("backend"));
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
