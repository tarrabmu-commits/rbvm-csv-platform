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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Trusted-local CSV-first public-intelligence and contextual-analysis transport.
 *
 * The uploaded CSV is the complete scope of one enrichment run. The public
 * enrichment stage never reads current Cases or tenant database state. Later
 * contextual analyses add only customer-declared context to that immutable run.
 * Every successful contextual analysis gets its own immutable analysisId and
 * preserves its submitted bundle, contextual technical-severity output, summary,
 * and risk-method-admission report. No stage calculates Organizational Risk.
 */
public final class CsvFirstEnrichmentHttpHandler implements HttpHandler {
    public static final String CONTRACT_ID = "CSV_FIRST_PUBLIC_INTELLIGENCE_HTTP_V1";
    public static final String ANALYSIS_CONTRACT_ID = "CSV_FIRST_CONTEXTUAL_ANALYSIS_HTTP_V1";

    private static final String ROOT = "/api/v1/csv-first-enrichments";
    private static final Pattern RUN_ARTIFACT_PATH = Pattern.compile(
            "^/api/v1/csv-first-enrichments/([0-9a-fA-F-]{36})/(csv|report|snapshot)$");
    private static final Pattern ANALYSIS_CREATE_PATH = Pattern.compile(
            "^/api/v1/csv-first-enrichments/([0-9a-fA-F-]{36})/analyses$");
    private static final Pattern ANALYSIS_ARTIFACT_PATH = Pattern.compile(
            "^/api/v1/csv-first-enrichments/([0-9a-fA-F-]{36})/analyses/"
                    + "([0-9a-fA-F-]{36})/(csv|summary|method-admission|customer-bundle)$");
    private static final Duration PROCESS_TIMEOUT = Duration.ofMinutes(10);
    private static final int MAX_PROCESS_OUTPUT_BYTES = 64 * 1024;

    private final Path dataDirectory;
    private final Path repositoryRoot;
    private final Path enrichmentScript;
    private final Path analysisScript;
    private final Path admissionScript;
    private final Path cacheDirectory;
    private final String python;
    private final long maximumUploadBytes;
    private final ApiKeyAuthenticator authenticator;

    public CsvFirstEnrichmentHttpHandler(
            Path dataDirectory,
            long maximumUploadBytes,
            ApiKeyAuthenticator authenticator
    ) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        this.maximumUploadBytes = maximumUploadBytes;
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        String configuredRoot = System.getenv().getOrDefault("RBVM_REPOSITORY_ROOT", ".");
        this.repositoryRoot = Path.of(configuredRoot).toAbsolutePath().normalize();
        this.enrichmentScript = repositoryRoot.resolve("scripts/enrich-uploaded-csv.py").normalize();
        this.analysisScript = repositoryRoot.resolve("scripts/analyze-csv-run-evidence.py").normalize();
        this.admissionScript = repositoryRoot.resolve("scripts/evaluate-rbvm-v2-method-candidates.py").normalize();
        this.cacheDirectory = this.dataDirectory.resolve("public-cve-intel-cache").normalize();
        this.python = System.getenv().getOrDefault("RBVM_PYTHON", "python3");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
            String path = exchange.getRequestURI().getPath();

            if (ROOT.equals(path)) {
                requireRole(exchange, ApiRole.OPERATOR);
                if (!"POST".equals(method)) {
                    methodNotAllowed(exchange, "POST");
                    return;
                }
                create(exchange);
                return;
            }

            Matcher analysisCreate = ANALYSIS_CREATE_PATH.matcher(path);
            if (analysisCreate.matches()) {
                requireRole(exchange, ApiRole.OPERATOR);
                if (!"POST".equals(method)) {
                    methodNotAllowed(exchange, "POST");
                    return;
                }
                UUID runId = parseRunId(exchange, analysisCreate.group(1));
                if (runId != null) contextualAnalysis(exchange, runId);
                return;
            }

            Matcher analysisArtifact = ANALYSIS_ARTIFACT_PATH.matcher(path);
            if (analysisArtifact.matches()) {
                requireRole(exchange, ApiRole.VIEWER);
                if (!"GET".equals(method)) {
                    methodNotAllowed(exchange, "GET");
                    return;
                }
                UUID runId = parseRunId(exchange, analysisArtifact.group(1));
                if (runId == null) return;
                UUID analysisId = parseAnalysisId(exchange, analysisArtifact.group(2));
                if (analysisId == null) return;
                analysisArtifact(exchange, runId, analysisId, analysisArtifact.group(3));
                return;
            }

            Matcher runArtifact = RUN_ARTIFACT_PATH.matcher(path);
            if (runArtifact.matches()) {
                requireRole(exchange, ApiRole.VIEWER);
                if (!"GET".equals(method)) {
                    methodNotAllowed(exchange, "GET");
                    return;
                }
                UUID runId = parseRunId(exchange, runArtifact.group(1));
                if (runId != null) runArtifact(exchange, runId, runArtifact.group(2));
                return;
            }

            problem(exchange, 404, "NOT_FOUND", "The requested CSV-first enrichment route does not exist");
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            exception.printStackTrace(System.err);
            problem(exchange, 500, "INTERNAL_ERROR", "The CSV-first enrichment request could not be completed");
        } finally {
            exchange.close();
        }
    }

    private void create(HttpExchange exchange) throws IOException {
        if (!regularScript(enrichmentScript)) {
            problem(exchange, 503, "CSV_FIRST_ENRICHMENT_UNAVAILABLE",
                    "CSV-first enrichment script is unavailable; configure RBVM_REPOSITORY_ROOT");
            return;
        }
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isCsvContentType(contentType)) {
            problem(exchange, 415, "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be text/csv, application/csv, or application/octet-stream");
            return;
        }
        if (requestTooLarge(exchange)) {
            problem(exchange, 413, "UPLOAD_TOO_LARGE", "CSV exceeds the configured upload limit");
            return;
        }

        UUID runId = UUID.randomUUID();
        Path run = runDirectory(runId);
        Files.createDirectories(run);
        Path input = run.resolve("input.csv");
        Path output = run.resolve("enriched.csv");
        Path snapshot = run.resolve("public-intel.json");
        Path report = run.resolve("report.json");
        Path collectorReport = run.resolve("collector-report.json");
        Path processLog = run.resolve("process.log");

        try (InputStream body = exchange.getRequestBody();
             OutputStream staged = Files.newOutputStream(input)) {
            copyBounded(body, staged, maximumUploadBytes);
        } catch (UploadTooLargeException exception) {
            deleteTree(run);
            problem(exchange, 413, "UPLOAD_TOO_LARGE", "CSV exceeds the configured upload limit");
            return;
        }

        ProcessBuilder builder = new ProcessBuilder(
                python,
                enrichmentScript.toString(),
                input.toString(),
                output.toString(),
                "--snapshot-output", snapshot.toString(),
                "--report", report.toString(),
                "--collector-report", collectorReport.toString(),
                "--cache-dir", cacheDirectory.toString()
        );
        ProcessOutcome outcome = runProcess(builder, processLog);
        if (outcome.interrupted()) {
            deleteTree(run);
            problem(exchange, 503, "CSV_FIRST_ENRICHMENT_INTERRUPTED", "CSV-first enrichment was interrupted");
            return;
        }
        if (outcome.timedOut()) {
            deleteTree(run);
            problem(exchange, 504, "CSV_FIRST_ENRICHMENT_TIMEOUT", "CSV-first enrichment exceeded the execution limit");
            return;
        }
        if (!outcome.success() || !Files.isRegularFile(output) || !Files.isRegularFile(report)) {
            String diagnostic = boundedDiagnostic(processLog);
            deleteTree(run);
            problem(exchange, 422, "CSV_FIRST_ENRICHMENT_FAILED",
                    diagnostic.isBlank() ? "CSV-first enrichment failed" : diagnostic);
            return;
        }
        Files.deleteIfExists(processLog);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("contractId", CONTRACT_ID);
        response.put("status", "COMPLETE");
        response.put("scope", "INPUT_CSV_ONLY");
        response.put("databaseStateUsed", false);
        response.put("runId", runId.toString());
        response.put("enrichedCsv", ROOT + "/" + runId + "/csv");
        response.put("report", ROOT + "/" + runId + "/report");
        response.put("snapshot", ROOT + "/" + runId + "/snapshot");
        response.put("contextualAnalyses", ROOT + "/" + runId + "/analyses");
        response.put("next", "/assets?tab=managed&setup=1&runId=" + runId);
        sendJson(exchange, 200, response);
    }

    private void contextualAnalysis(HttpExchange exchange, UUID runId) throws IOException {
        if (!regularScript(analysisScript) || !regularScript(admissionScript)) {
            problem(exchange, 503, "CSV_FIRST_CONTEXTUAL_ANALYSIS_UNAVAILABLE",
                    "CSV-first contextual-analysis scripts are unavailable; configure RBVM_REPOSITORY_ROOT");
            return;
        }
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isJsonContentType(contentType)) {
            problem(exchange, 415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json");
            return;
        }
        if (requestTooLarge(exchange)) {
            problem(exchange, 413, "UPLOAD_TOO_LARGE", "Customer context exceeds the configured upload limit");
            return;
        }

        Path run = runDirectory(runId);
        Path enriched = run.resolve("enriched.csv");
        if (!Files.isRegularFile(enriched) || Files.isSymbolicLink(enriched)) {
            problem(exchange, 404, "RUN_NOT_FOUND", "CSV-first enrichment run does not exist");
            return;
        }

        UUID analysisId = UUID.randomUUID();
        Path analysisDirectory = analysisDirectory(runId, analysisId);
        Files.createDirectories(analysisDirectory);
        Path bundle = analysisDirectory.resolve("customer-bundle.json");
        Path analysis = analysisDirectory.resolve("analysis.csv");
        Path summary = analysisDirectory.resolve("analysis-summary.json");
        Path admission = analysisDirectory.resolve("method-admission.json");
        Path analysisLog = analysisDirectory.resolve("analysis-process.log");
        Path admissionLog = analysisDirectory.resolve("admission-process.log");

        try (InputStream body = exchange.getRequestBody();
             OutputStream staged = Files.newOutputStream(bundle)) {
            copyBounded(body, staged, maximumUploadBytes);
        } catch (UploadTooLargeException exception) {
            deleteTree(analysisDirectory);
            problem(exchange, 413, "UPLOAD_TOO_LARGE", "Customer context exceeds the configured upload limit");
            return;
        }

        ProcessBuilder analyzer = new ProcessBuilder(
                python,
                analysisScript.toString(),
                enriched.toString(),
                analysis.toString(),
                summary.toString(),
                "--customer-bundle", bundle.toString()
        );
        ProcessOutcome analysisOutcome = runProcess(analyzer, analysisLog);
        if (analysisOutcome.interrupted()) {
            deleteTree(analysisDirectory);
            problem(exchange, 503, "CSV_FIRST_CONTEXTUAL_ANALYSIS_INTERRUPTED", "Contextual analysis was interrupted");
            return;
        }
        if (analysisOutcome.timedOut()) {
            deleteTree(analysisDirectory);
            problem(exchange, 504, "CSV_FIRST_CONTEXTUAL_ANALYSIS_TIMEOUT", "Contextual analysis exceeded the execution limit");
            return;
        }
        if (!analysisOutcome.success() || !Files.isRegularFile(analysis) || !Files.isRegularFile(summary)) {
            String diagnostic = boundedDiagnostic(analysisLog);
            deleteTree(analysisDirectory);
            problem(exchange, 422, "CSV_FIRST_CONTEXTUAL_ANALYSIS_FAILED",
                    diagnostic.isBlank() ? "Customer context could not be analyzed" : diagnostic);
            return;
        }
        Files.deleteIfExists(analysisLog);

        ProcessBuilder admissionBuilder = new ProcessBuilder(
                python,
                admissionScript.toString(),
                analysis.toString(),
                admission.toString()
        );
        ProcessOutcome admissionOutcome = runProcess(admissionBuilder, admissionLog);
        if (admissionOutcome.interrupted()) {
            deleteTree(analysisDirectory);
            problem(exchange, 503, "CSV_FIRST_METHOD_ADMISSION_INTERRUPTED", "Risk-method admission was interrupted");
            return;
        }
        if (admissionOutcome.timedOut()) {
            deleteTree(analysisDirectory);
            problem(exchange, 504, "CSV_FIRST_METHOD_ADMISSION_TIMEOUT", "Risk-method admission exceeded the execution limit");
            return;
        }
        if (!admissionOutcome.success() || !Files.isRegularFile(admission)) {
            String diagnostic = boundedDiagnostic(admissionLog);
            deleteTree(analysisDirectory);
            problem(exchange, 422, "CSV_FIRST_METHOD_ADMISSION_FAILED",
                    diagnostic.isBlank() ? "Risk-method admission could not be evaluated" : diagnostic);
            return;
        }
        Files.deleteIfExists(admissionLog);

        String analysisRoot = ROOT + "/" + runId + "/analyses/" + analysisId;
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("contractId", ANALYSIS_CONTRACT_ID);
        response.put("status", "COMPLETE");
        response.put("scope", "INPUT_CSV_PLUS_CUSTOMER_DECLARED_CONTEXT");
        response.put("databaseStateUsed", false);
        response.put("runId", runId.toString());
        response.put("analysisId", analysisId.toString());
        response.put("immutable", true);
        response.put("customerBundle", analysisRoot + "/customer-bundle");
        response.put("analysisCsv", analysisRoot + "/csv");
        response.put("analysisSummary", analysisRoot + "/summary");
        response.put("methodAdmission", analysisRoot + "/method-admission");
        response.put("outputSemantics", "CONTEXTUAL_TECHNICAL_SEVERITY_PLUS_INDEPENDENT_EVIDENCE");
        response.put("organizationalRisk", "NON_COMPUTABLE");
        sendJson(exchange, 201, response);
    }

    private void runArtifact(HttpExchange exchange, UUID runId, String type) throws IOException {
        Path run = runDirectory(runId);
        Path file;
        String contentType;
        String downloadName;
        switch (type) {
            case "csv" -> {
                file = run.resolve("enriched.csv");
                contentType = "text/csv; charset=utf-8";
                downloadName = "rbvm-enriched-" + runId + ".csv";
            }
            case "report" -> {
                file = run.resolve("report.json");
                contentType = "application/json; charset=utf-8";
                downloadName = "rbvm-enrichment-report-" + runId + ".json";
            }
            case "snapshot" -> {
                file = run.resolve("public-intel.json");
                contentType = "application/json; charset=utf-8";
                downloadName = "rbvm-public-intel-" + runId + ".json";
            }
            default -> throw new IllegalStateException("unexpected run artifact type");
        }
        sendArtifact(exchange, file, contentType, downloadName);
    }

    private void analysisArtifact(
            HttpExchange exchange,
            UUID runId,
            UUID analysisId,
            String type
    ) throws IOException {
        Path directory = analysisDirectory(runId, analysisId);
        Path file;
        String contentType;
        String downloadName;
        switch (type) {
            case "csv" -> {
                file = directory.resolve("analysis.csv");
                contentType = "text/csv; charset=utf-8";
                downloadName = "rbvm-contextual-analysis-" + runId + "-" + analysisId + ".csv";
            }
            case "summary" -> {
                file = directory.resolve("analysis-summary.json");
                contentType = "application/json; charset=utf-8";
                downloadName = "rbvm-contextual-analysis-summary-" + runId + "-" + analysisId + ".json";
            }
            case "method-admission" -> {
                file = directory.resolve("method-admission.json");
                contentType = "application/json; charset=utf-8";
                downloadName = "rbvm-method-admission-" + runId + "-" + analysisId + ".json";
            }
            case "customer-bundle" -> {
                file = directory.resolve("customer-bundle.json");
                contentType = "application/json; charset=utf-8";
                downloadName = "rbvm-customer-bundle-" + runId + "-" + analysisId + ".json";
            }
            default -> throw new IllegalStateException("unexpected analysis artifact type");
        }
        sendArtifact(exchange, file, contentType, downloadName);
    }

    private static void sendArtifact(
            HttpExchange exchange,
            Path file,
            String contentType,
            String downloadName
    ) throws IOException {
        if (!Files.isRegularFile(file) || Files.isSymbolicLink(file)) {
            problem(exchange, 404, "ARTIFACT_NOT_FOUND", "CSV-first artifact does not exist");
            return;
        }
        exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + downloadName + "\"");
        sendBytes(exchange, 200, contentType, Files.readAllBytes(file));
    }

    private Path runDirectory(UUID runId) throws IOException {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        if (!run.startsWith(runs)) throw new IOException("invalid run directory");
        return run;
    }

    private Path analysisDirectory(UUID runId, UUID analysisId) throws IOException {
        Path run = runDirectory(runId);
        Path analyses = run.resolve("analyses").normalize();
        Path analysis = analyses.resolve(analysisId.toString()).normalize();
        if (!analysis.startsWith(analyses)) throw new IOException("invalid analysis directory");
        return analysis;
    }

    private UUID parseRunId(HttpExchange exchange, String value) throws IOException {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            problem(exchange, 400, "INVALID_RUN_ID", "Invalid CSV-first enrichment run identifier");
            return null;
        }
    }

    private UUID parseAnalysisId(HttpExchange exchange, String value) throws IOException {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            problem(exchange, 400, "INVALID_ANALYSIS_ID", "Invalid CSV-first contextual-analysis identifier");
            return null;
        }
    }

    private ProcessOutcome runProcess(ProcessBuilder builder, Path processLog) throws IOException {
        builder.directory(repositoryRoot.toFile());
        builder.redirectErrorStream(true);
        builder.redirectOutput(processLog.toFile());
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

    private static boolean regularScript(Path path) {
        return Files.isRegularFile(path) && !Files.isSymbolicLink(path);
    }

    private boolean requestTooLarge(HttpExchange exchange) {
        long length = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        return length > maximumUploadBytes;
    }

    private static String boundedDiagnostic(Path processLog) throws IOException {
        byte[] processOutput = Files.isRegularFile(processLog) ? Files.readAllBytes(processLog) : new byte[0];
        return new String(
                processOutput,
                0,
                Math.min(processOutput.length, MAX_PROCESS_OUTPUT_BYTES),
                StandardCharsets.UTF_8
        ).trim();
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        Optional<AuthPrincipal> principal = authenticator.authenticate(authorization);
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
        }
    }

    private static boolean isCsvContentType(String value) {
        if (value == null) return false;
        String normalized = value.toLowerCase(Locale.ROOT).split(";", 2)[0].trim();
        return "text/csv".equals(normalized)
                || "application/csv".equals(normalized)
                || "application/octet-stream".equals(normalized);
    }

    private static boolean isJsonContentType(String value) {
        if (value == null) return false;
        String normalized = value.toLowerCase(Locale.ROOT).split(";", 2)[0].trim();
        return "application/json".equals(normalized) || normalized.endsWith("+json");
    }

    private static long parseContentLength(String value) {
        if (value == null || value.isBlank()) return -1;
        try {
            long parsed = Long.parseLong(value);
            return parsed < 0 ? -1 : parsed;
        } catch (NumberFormatException exception) {
            return -1;
        }
    }

    private static void copyBounded(InputStream input, OutputStream output, long maximumBytes)
            throws IOException, UploadTooLargeException {
        byte[] buffer = new byte[8192];
        long total = 0;
        int read;
        while ((read = input.read(buffer)) >= 0) {
            if (read == 0) continue;
            total += read;
            if (total > maximumBytes) throw new UploadTooLargeException();
            output.write(buffer, 0, read);
        }
    }

    private static void deleteTree(Path directory) {
        if (directory == null || !Files.exists(directory)) return;
        try (var paths = Files.walk(directory)) {
            paths.sorted((left, right) -> right.getNameCount() - left.getNameCount())
                    .forEach(path -> {
                        try { Files.deleteIfExists(path); } catch (IOException ignored) { }
                    });
        } catch (IOException ignored) { }
    }

    private static void methodNotAllowed(HttpExchange exchange, String allowed) throws IOException {
        exchange.getResponseHeaders().set("Allow", allowed);
        problem(exchange, 405, "METHOD_NOT_ALLOWED", "HTTP method is not allowed for this resource");
    }

    private static void problem(HttpExchange exchange, int status, String code, String detail) throws IOException {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("type", "about:blank");
        value.put("title", code);
        value.put("status", status);
        value.put("detail", detail);
        sendJson(exchange, status, value);
    }

    private static void sendJson(HttpExchange exchange, int status, Map<String, ?> value) throws IOException {
        sendBytes(exchange, status, "application/json; charset=utf-8",
                JsonOutput.object(value).getBytes(StandardCharsets.UTF_8));
    }

    private static void sendBytes(HttpExchange exchange, int status, String contentType, byte[] bytes)
            throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType);
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private record ProcessOutcome(boolean success, boolean timedOut, boolean interrupted) { }

    private static final class UploadTooLargeException extends Exception {
        private static final long serialVersionUID = 1L;
    }
}
