package io.rbvm.csv;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CSV-first organizational-risk transport over immutable contextual analyses.
 *
 * <p>Risk methods are explicitly selected per analysis. Results are append-only,
 * keyed by the pinned method-definition SHA, and never mutate the source analysis.
 * Vendor-style methods are benchmark configurations and are not represented as
 * equivalent to a vendor tenant's current scoring configuration.</p>
 */
public final class CsvFirstRiskHttpHandler implements HttpHandler {
    public static final String METHODS_ROOT = "/api/v1/csv-first-risk-methods";
    public static final String READINESS_ROOT = "/api/v1/csv-first-risk-readiness";
    public static final String RISKS_ROOT = "/api/v1/csv-first-risks";
    public static final String CONTRACT_ID = "CSV_FIRST_RISK_HTTP_V1";

    private static final Duration PROCESS_TIMEOUT = Duration.ofMinutes(10);
    private static final int MAX_PROCESS_OUTPUT_BYTES = 64 * 1024;
    private static final Set<String> PROCESS_ENV_ALLOWLIST = Set.of(
            "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT"
    );

    private static final Pattern READINESS_PATH = Pattern.compile(
            "^" + READINESS_ROOT + "/([0-9a-fA-F-]{36})/([0-9a-fA-F-]{36})$");
    private static final Pattern RISK_CREATE_PATH = Pattern.compile(
            "^" + RISKS_ROOT + "/([0-9a-fA-F-]{36})/([0-9a-fA-F-]{36})/([A-Z0-9_]+)$");
    private static final Pattern RISK_ARTIFACT_PATH = Pattern.compile(
            "^" + RISKS_ROOT + "/([0-9a-fA-F-]{36})/([0-9a-fA-F-]{36})/"
                    + "([A-Z0-9_]+)/(csv|report|method)$");

    private static final List<MethodSpec> METHODS = List.of(
            new MethodSpec(
                    "RBVM_CSV_BOUNDED_RISK_V1",
                    "RBVM_CSV_BOUNDED_RISK_V1.json",
                    1,
                    "RBVM_LOCAL_POLICY",
                    "RBVM",
                    "0..10",
                    "f4c3b8c3aed6c68b2767caefa7a70e49f968ad00e6fa91f3a4ed397fadc1b0e1"
            ),
            new MethodSpec(
                    "JUPITERONE_STYLE_CSV_V1",
                    "JUPITERONE_STYLE_CSV_V1.json",
                    1,
                    "VENDOR_STYLE_BENCHMARK",
                    "JupiterOne",
                    "0..1",
                    "27521ffbabb17e3b7c74f212e5bc7e6781e8b8d1c58c30ec4194386b6af02fd6"
            ),
            new MethodSpec(
                    "SERVICENOW_STYLE_CSV_V1",
                    "SERVICENOW_STYLE_CSV_V1.json",
                    1,
                    "VENDOR_STYLE_BENCHMARK",
                    "ServiceNow",
                    "0..100",
                    "ad73605f0f24d7303cf6fa2eafb0724460ca98c2edd766db07efe134a9e5be7d"
            ),
            new MethodSpec(
                    "BRINQA_STYLE_CSV_V1",
                    "BRINQA_STYLE_CSV_V1.json",
                    1,
                    "VENDOR_STYLE_BENCHMARK",
                    "Brinqa",
                    "0..10",
                    "d3e2385226e8d9c65a9e4c33b2ca541822563e0795f49c4a971e5af00520deb3"
            )
    );

    private final Path dataDirectory;
    private final ApiKeyAuthenticator authenticator;
    private final Path repositoryRoot;
    private final Path evaluatorScript;
    private final Path methodsDirectory;
    private final String python;

    public CsvFirstRiskHttpHandler(Path dataDirectory, ApiKeyAuthenticator authenticator) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        this.repositoryRoot = Path.of(System.getenv().getOrDefault("RBVM_REPOSITORY_ROOT", "."))
                .toAbsolutePath().normalize();
        this.evaluatorScript = repositoryRoot.resolve("scripts/evaluate-csv-first-risk.py").normalize();
        this.methodsDirectory = repositoryRoot.resolve(
                "docs/fixtures/csv-first-risk-methods").normalize();
        this.python = System.getenv().getOrDefault("RBVM_PYTHON", "python3");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
            String path = exchange.getRequestURI().getPath();

            if (METHODS_ROOT.equals(path)) {
                requireRole(exchange, ApiRole.VIEWER);
                if (!"GET".equals(method)) {
                    methodNotAllowed(exchange, "GET");
                    return;
                }
                catalog(exchange);
                return;
            }

            Matcher readiness = READINESS_PATH.matcher(path);
            if (readiness.matches()) {
                requireRole(exchange, ApiRole.VIEWER);
                if (!"GET".equals(method)) {
                    methodNotAllowed(exchange, "GET");
                    return;
                }
                UUID runId = parseId(exchange, readiness.group(1), "INVALID_RUN_ID");
                if (runId == null) return;
                UUID analysisId = parseId(exchange, readiness.group(2), "INVALID_ANALYSIS_ID");
                if (analysisId == null) return;
                readiness(exchange, runId, analysisId);
                return;
            }

            Matcher artifact = RISK_ARTIFACT_PATH.matcher(path);
            if (artifact.matches()) {
                requireRole(exchange, ApiRole.VIEWER);
                if (!"GET".equals(method)) {
                    methodNotAllowed(exchange, "GET");
                    return;
                }
                UUID runId = parseId(exchange, artifact.group(1), "INVALID_RUN_ID");
                if (runId == null) return;
                UUID analysisId = parseId(exchange, artifact.group(2), "INVALID_ANALYSIS_ID");
                if (analysisId == null) return;
                MethodSpec spec = method(exchange, artifact.group(3));
                if (spec == null) return;
                artifact(exchange, runId, analysisId, spec, artifact.group(4));
                return;
            }

            Matcher create = RISK_CREATE_PATH.matcher(path);
            if (create.matches()) {
                requireRole(exchange, ApiRole.OPERATOR);
                if (!"POST".equals(method)) {
                    methodNotAllowed(exchange, "POST");
                    return;
                }
                UUID runId = parseId(exchange, create.group(1), "INVALID_RUN_ID");
                if (runId == null) return;
                UUID analysisId = parseId(exchange, create.group(2), "INVALID_ANALYSIS_ID");
                if (analysisId == null) return;
                MethodSpec spec = method(exchange, create.group(3));
                if (spec == null) return;
                materialize(exchange, runId, analysisId, spec);
                return;
            }

            problem(exchange, 404, "NOT_FOUND", "The requested CSV-first risk route does not exist");
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            exception.printStackTrace(System.err);
            problem(exchange, 500, "INTERNAL_ERROR", "CSV-first risk request failed");
        } finally {
            exchange.close();
        }
    }

    private void catalog(HttpExchange exchange) throws IOException {
        ensureRuntime();
        List<Map<String, Object>> methods = new ArrayList<>();
        for (MethodSpec spec : METHODS) {
            Path fixture = methodFixture(spec);
            verifyMethodFixture(spec, fixture);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("methodId", spec.methodId());
            item.put("methodVersion", spec.methodVersion());
            item.put("methodSha256", spec.expectedSha256());
            item.put("classification", spec.classification());
            item.put("provider", spec.provider());
            item.put("nativeScale", spec.nativeScale());
            methods.add(item);
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("contractId", CONTRACT_ID);
        response.put("selectionSemantics", "EXPLICIT_PER_ANALYSIS_NO_IMPLICIT_DEFAULT");
        response.put("methods", methods);
        sendJson(exchange, 200, response);
    }

    private void readiness(HttpExchange exchange, UUID runId, UUID analysisId) throws IOException {
        ensureRuntime();
        for (MethodSpec spec : METHODS) {
            verifyMethodFixture(spec, methodFixture(spec));
        }
        Path analysis = sourceAnalysis(runId, analysisId);
        if (analysis == null) {
            problem(exchange, 404, "ANALYSIS_NOT_FOUND", "Immutable CSV-first contextual analysis does not exist");
            return;
        }
        Path directory = analysis.getParent();
        Path output = directory.resolve(".risk-readiness-" + UUID.randomUUID() + ".json").normalize();
        Path log = directory.resolve(".risk-readiness-" + UUID.randomUUID() + ".log").normalize();
        if (!output.startsWith(directory) || !log.startsWith(directory)) {
            throw new IOException("invalid risk-readiness staging path");
        }
        try {
            ProcessOutcome outcome = runProcess(new ProcessBuilder(
                    python,
                    evaluatorScript.toString(),
                    "readiness",
                    analysis.toString(),
                    methodsDirectory.toString(),
                    output.toString()
            ), log);
            if (outcome.interrupted()) {
                problem(exchange, 503, "CSV_FIRST_RISK_READINESS_INTERRUPTED",
                        "Risk readiness evaluation was interrupted");
                return;
            }
            if (outcome.timedOut()) {
                problem(exchange, 504, "CSV_FIRST_RISK_READINESS_TIMEOUT",
                        "Risk readiness evaluation exceeded the execution limit");
                return;
            }
            if (!outcome.success() || !regularFile(output)) {
                String diagnostic = boundedDiagnostic(log);
                problem(exchange, 422, "CSV_FIRST_RISK_READINESS_FAILED",
                        diagnostic.isBlank() ? "Risk readiness could not be evaluated" : diagnostic);
                return;
            }
            sendBytes(exchange, 200, "application/json; charset=utf-8", Files.readAllBytes(output));
        } finally {
            Files.deleteIfExists(output);
            Files.deleteIfExists(log);
        }
    }

    private void materialize(
            HttpExchange exchange,
            UUID runId,
            UUID analysisId,
            MethodSpec spec
    ) throws IOException {
        ensureRuntime();
        Path fixture = methodFixture(spec);
        verifyMethodFixture(spec, fixture);
        Path analysis = sourceAnalysis(runId, analysisId);
        if (analysis == null) {
            problem(exchange, 404, "ANALYSIS_NOT_FOUND", "Immutable CSV-first contextual analysis does not exist");
            return;
        }

        Path target = riskDirectory(runId, analysisId, spec.expectedSha256());
        if (published(target)) {
            sendCreated(exchange, runId, analysisId, spec, true, 200);
            return;
        }
        if (Files.exists(target)) {
            problem(exchange, 409, "RISK_ARTIFACT_CONFLICT",
                    "Risk target exists but is incomplete; manual integrity review is required");
            return;
        }

        Path analysisDirectory = analysis.getParent();
        Path riskRoot = target.getParent();
        Files.createDirectories(riskRoot);
        Path staging = analysisDirectory.resolve(".risk-stage-" + UUID.randomUUID()).normalize();
        if (!staging.startsWith(analysisDirectory)) {
            throw new IOException("invalid risk staging directory");
        }
        Files.createDirectories(staging);

        Path pinnedMethod = staging.resolve("method-definition.json");
        Path riskCsv = staging.resolve("risk.csv");
        Path report = staging.resolve("risk-report.json");
        Path log = staging.resolve("process.log");
        Files.copy(fixture, pinnedMethod);

        ProcessOutcome outcome = runProcess(new ProcessBuilder(
                python,
                evaluatorScript.toString(),
                "evaluate",
                analysis.toString(),
                pinnedMethod.toString(),
                riskCsv.toString(),
                report.toString()
        ), log);
        if (outcome.interrupted()) {
            deleteTree(staging);
            problem(exchange, 503, "CSV_FIRST_RISK_INTERRUPTED", "Risk derivation was interrupted");
            return;
        }
        if (outcome.timedOut()) {
            deleteTree(staging);
            problem(exchange, 504, "CSV_FIRST_RISK_TIMEOUT", "Risk derivation exceeded the execution limit");
            return;
        }
        if (!outcome.success() || !regularFile(riskCsv) || !regularFile(report)) {
            String diagnostic = boundedDiagnostic(log);
            deleteTree(staging);
            problem(exchange, 422, "CSV_FIRST_RISK_FAILED",
                    diagnostic.isBlank() ? "Risk could not be derived" : diagnostic);
            return;
        }
        Files.deleteIfExists(log);

        try {
            Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (FileAlreadyExistsException exception) {
            deleteTree(staging);
            if (!published(target)) {
                problem(exchange, 409, "RISK_ARTIFACT_CONFLICT",
                        "Concurrent risk publication produced an incomplete target");
                return;
            }
            sendCreated(exchange, runId, analysisId, spec, true, 200);
            return;
        } catch (AtomicMoveNotSupportedException exception) {
            deleteTree(staging);
            problem(exchange, 503, "ATOMIC_RISK_PUBLICATION_UNAVAILABLE",
                    "Filesystem does not support atomic risk-artifact publication");
            return;
        }

        if (!published(target)) {
            problem(exchange, 500, "RISK_PUBLICATION_INTEGRITY_FAILURE",
                    "Published risk artifacts failed integrity checks");
            return;
        }
        sendCreated(exchange, runId, analysisId, spec, false, 201);
    }

    private void artifact(
            HttpExchange exchange,
            UUID runId,
            UUID analysisId,
            MethodSpec spec,
            String type
    ) throws IOException {
        verifyMethodFixture(spec, methodFixture(spec));
        Path target = riskDirectory(runId, analysisId, spec.expectedSha256());
        Path file;
        String contentType;
        String downloadName;
        switch (type) {
            case "csv" -> {
                file = target.resolve("risk.csv");
                contentType = "text/csv; charset=utf-8";
                downloadName = "rbvm-risk-" + spec.methodId() + "-" + runId + "-" + analysisId + ".csv";
            }
            case "report" -> {
                file = target.resolve("risk-report.json");
                contentType = "application/json; charset=utf-8";
                downloadName = "rbvm-risk-report-" + spec.methodId() + "-" + runId + "-" + analysisId + ".json";
            }
            case "method" -> {
                file = target.resolve("method-definition.json");
                contentType = "application/json; charset=utf-8";
                downloadName = spec.methodId() + ".json";
            }
            default -> throw new IllegalStateException("unexpected risk artifact type");
        }
        if (!regularFile(file)) {
            problem(exchange, 404, "RISK_ARTIFACT_NOT_FOUND", "CSV-first risk artifact does not exist");
            return;
        }
        exchange.getResponseHeaders().set(
                "Content-Disposition", "attachment; filename=\"" + downloadName + "\"");
        sendBytes(exchange, 200, contentType, Files.readAllBytes(file));
    }

    private void sendCreated(
            HttpExchange exchange,
            UUID runId,
            UUID analysisId,
            MethodSpec spec,
            boolean replayed,
            int status
    ) throws IOException {
        String root = RISKS_ROOT + "/" + runId + "/" + analysisId + "/" + spec.methodId();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("contractId", CONTRACT_ID);
        response.put("status", "COMPLETE");
        response.put("runId", runId.toString());
        response.put("analysisId", analysisId.toString());
        response.put("methodId", spec.methodId());
        response.put("methodVersion", spec.methodVersion());
        response.put("methodSha256", spec.expectedSha256());
        response.put("classification", spec.classification());
        response.put("provider", spec.provider());
        response.put("nativeScale", spec.nativeScale());
        response.put("sourceAnalysisImmutable", true);
        response.put("derivedArtifactsImmutable", true);
        response.put("replayed", replayed);
        response.put("riskCsv", root + "/csv");
        response.put("riskReport", root + "/report");
        response.put("methodDefinition", root + "/method");
        sendJson(exchange, status, response);
    }

    private void ensureRuntime() throws IOException {
        if (!regularFile(evaluatorScript) || !Files.isDirectory(methodsDirectory)) {
            throw new IOException("CSV-first risk runtime is unavailable; configure RBVM_REPOSITORY_ROOT");
        }
    }

    private Path methodFixture(MethodSpec spec) {
        return methodsDirectory.resolve(spec.fileName()).normalize();
    }

    private void verifyMethodFixture(MethodSpec spec, Path fixture) throws IOException {
        if (!fixture.startsWith(methodsDirectory) || !regularFile(fixture)) {
            throw new IOException("risk method fixture is unavailable: " + spec.methodId());
        }
        String actual = sha256(fixture);
        if (!spec.expectedSha256().equals(actual)) {
            throw new IOException("risk method fixture SHA drift: " + spec.methodId() + " actual=" + actual);
        }
    }

    private MethodSpec method(HttpExchange exchange, String methodId) throws IOException {
        for (MethodSpec spec : METHODS) {
            if (spec.methodId().equals(methodId)) return spec;
        }
        problem(exchange, 404, "RISK_METHOD_NOT_FOUND", "Unknown CSV-first risk method");
        return null;
    }

    private Path sourceAnalysis(UUID runId, UUID analysisId) throws IOException {
        Path directory = analysisDirectory(runId, analysisId);
        Path source = directory.resolve("analysis.csv").normalize();
        if (!source.startsWith(directory) || !regularFile(source)) return null;
        return source;
    }

    private Path analysisDirectory(UUID runId, UUID analysisId) throws IOException {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        Path analyses = run.resolve("analyses").normalize();
        Path analysis = analyses.resolve(analysisId.toString()).normalize();
        if (!run.startsWith(runs) || !analyses.startsWith(run) || !analysis.startsWith(analyses)) {
            throw new IOException("invalid analysis directory");
        }
        return analysis;
    }

    private Path riskDirectory(UUID runId, UUID analysisId, String methodSha256) throws IOException {
        Path analysis = analysisDirectory(runId, analysisId);
        Path root = analysis.resolve("risk").normalize();
        Path target = root.resolve(methodSha256).normalize();
        if (!root.startsWith(analysis) || !target.startsWith(root)) {
            throw new IOException("invalid risk directory");
        }
        return target;
    }

    private boolean published(Path target) {
        if (!Files.isDirectory(target) || Files.isSymbolicLink(target)) return false;
        return regularFile(target.resolve("risk.csv"))
                && regularFile(target.resolve("risk-report.json"))
                && regularFile(target.resolve("method-definition.json"));
    }

    private ProcessOutcome runProcess(ProcessBuilder builder, Path log) throws IOException {
        builder.directory(repositoryRoot.toFile());
        restrictEnvironment(builder.environment(), System.getenv());
        builder.redirectErrorStream(true);
        builder.redirectOutput(log.toFile());
        Process process = builder.start();
        boolean finished;
        try {
            finished = process.waitFor(PROCESS_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return new ProcessOutcome(false, false, true);
        }
        if (!finished) {
            process.destroyForcibly();
            return new ProcessOutcome(false, true, false);
        }
        return new ProcessOutcome(process.exitValue() == 0, false, false);
    }

    static void restrictEnvironment(Map<String, String> target, Map<String, String> inherited) {
        target.clear();
        for (String key : PROCESS_ENV_ALLOWLIST) {
            String value = inherited.get(key);
            if (value != null && !value.isBlank()) target.put(key, value);
        }
        target.put("PYTHONIOENCODING", "utf-8");
        target.put("PYTHONUTF8", "1");
        target.put("PYTHONUNBUFFERED", "1");
    }

    private static String boundedDiagnostic(Path log) throws IOException {
        if (!regularFile(log)) return "";
        byte[] bytes;
        try (InputStream input = Files.newInputStream(log)) {
            bytes = input.readNBytes(MAX_PROCESS_OUTPUT_BYTES);
        }
        return new String(bytes, StandardCharsets.UTF_8).trim();
    }

    private static String sha256(Path path) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = Files.newInputStream(path)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    if (read > 0) digest.update(buffer, 0, read);
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IOException("SHA-256 is unavailable", exception);
        }
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        Optional<AuthPrincipal> principal = authenticator.authenticate(
                exchange.getRequestHeaders().getFirst("Authorization"));
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
        }
    }

    private UUID parseId(HttpExchange exchange, String value, String code) throws IOException {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            problem(exchange, 400, code, "Invalid CSV-first identifier");
            return null;
        }
    }

    private static boolean regularFile(Path path) {
        return Files.isRegularFile(path) && !Files.isSymbolicLink(path);
    }

    private static void deleteTree(Path directory) {
        if (directory == null || !Files.exists(directory)) return;
        try (var paths = Files.walk(directory)) {
            paths.sorted((left, right) -> right.getNameCount() - left.getNameCount())
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (IOException ignored) {
                            // Best-effort cleanup after a failed derivation.
                        }
                    });
        } catch (IOException ignored) {
            // Best-effort cleanup after a failed derivation.
        }
    }

    private static void methodNotAllowed(HttpExchange exchange, String allowed) throws IOException {
        exchange.getResponseHeaders().set("Allow", allowed);
        problem(exchange, 405, "METHOD_NOT_ALLOWED", "HTTP method is not allowed for this resource");
    }

    private static void problem(
            HttpExchange exchange,
            int status,
            String code,
            String detail
    ) throws IOException {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("type", "about:blank");
        value.put("title", code);
        value.put("status", status);
        value.put("detail", detail);
        sendJson(exchange, status, value);
    }

    private static void sendJson(
            HttpExchange exchange,
            int status,
            Map<String, ?> value
    ) throws IOException {
        sendBytes(
                exchange,
                status,
                "application/json; charset=utf-8",
                JsonOutput.object(value).getBytes(StandardCharsets.UTF_8)
        );
    }

    private static void sendBytes(
            HttpExchange exchange,
            int status,
            String contentType,
            byte[] bytes
    ) throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType);
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private record MethodSpec(
            String methodId,
            String fileName,
            int methodVersion,
            String classification,
            String provider,
            String nativeScale,
            String expectedSha256
    ) {
    }

    private record ProcessOutcome(boolean success, boolean timedOut, boolean interrupted) {
    }
}
