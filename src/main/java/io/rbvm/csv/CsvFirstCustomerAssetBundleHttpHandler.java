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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
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
 * Run-scoped local persistence transport for the customer-declared asset bundle.
 *
 * <p>This endpoint stores the exact JSON artifact supplied by the customer UI.
 * It deliberately does not infer, normalize, or translate customer evidence.
 * Semantic validation remains owned by the versioned customer-bundle contract.
 * A saved bundle can also be materialized into the established immutable
 * contextual-analysis pipeline without asking the client to upload it again.</p>
 */
public final class CsvFirstCustomerAssetBundleHttpHandler implements HttpHandler {
    public static final String ROOT = "/api/v1/csv-first-customer-assets";
    private static final String ARTIFACT_NAME = "customer-assets-v4.json";
    private static final Pattern ITEM_PATH = Pattern.compile(
            "^" + ROOT + "/([0-9a-fA-F-]{36})$");
    private static final Pattern ANALYSIS_PATH = Pattern.compile(
            "^" + ROOT + "/([0-9a-fA-F-]{36})/analyses$");
    private static final Duration PROCESS_TIMEOUT = Duration.ofMinutes(10);
    private static final int MAX_PROCESS_OUTPUT_BYTES = 64 * 1024;

    private final Path dataDirectory;
    private final long maximumUploadBytes;
    private final ApiKeyAuthenticator authenticator;
    private final Path repositoryRoot;
    private final Path analysisScript;
    private final Path admissionScript;
    private final String python;

    public CsvFirstCustomerAssetBundleHttpHandler(
            Path dataDirectory,
            long maximumUploadBytes,
            ApiKeyAuthenticator authenticator
    ) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        if (maximumUploadBytes < 1) {
            throw new IllegalArgumentException("maximumUploadBytes must be positive");
        }
        this.maximumUploadBytes = maximumUploadBytes;
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        this.repositoryRoot = Path.of(System.getenv().getOrDefault("RBVM_REPOSITORY_ROOT", "."))
                .toAbsolutePath().normalize();
        this.analysisScript = repositoryRoot.resolve("scripts/analyze-csv-run-evidence.py").normalize();
        this.admissionScript = repositoryRoot.resolve("scripts/evaluate-rbvm-v2-method-candidates.py").normalize();
        this.python = System.getenv().getOrDefault("RBVM_PYTHON", "python3");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);

            Matcher analysisMatcher = ANALYSIS_PATH.matcher(path);
            if (analysisMatcher.matches()) {
                UUID runId = parseRunId(exchange, analysisMatcher.group(1));
                if (runId == null) return;
                requireRole(exchange, ApiRole.OPERATOR);
                if (!"POST".equals(method)) {
                    exchange.getResponseHeaders().set("Allow", "POST");
                    problem(exchange, 405, "METHOD_NOT_ALLOWED", "Use POST");
                    return;
                }
                analyzeSaved(exchange, runId);
                return;
            }

            Matcher matcher = ITEM_PATH.matcher(path);
            if (!matcher.matches()) {
                problem(exchange, 404, "NOT_FOUND", "Customer asset bundle endpoint not found");
                return;
            }

            UUID runId = parseRunId(exchange, matcher.group(1));
            if (runId == null) return;

            switch (method) {
                case "GET" -> {
                    requireRole(exchange, ApiRole.VIEWER);
                    read(exchange, runId);
                }
                case "PUT" -> {
                    requireRole(exchange, ApiRole.OPERATOR);
                    write(exchange, runId);
                }
                default -> {
                    exchange.getResponseHeaders().set("Allow", "GET, PUT");
                    problem(exchange, 405, "METHOD_NOT_ALLOWED", "Use GET or PUT");
                }
            }
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            exception.printStackTrace(System.err);
            problem(exchange, 500, "INTERNAL_ERROR", "Customer asset bundle request failed");
        } finally {
            exchange.close();
        }
    }

    private void read(HttpExchange exchange, UUID runId) throws IOException {
        Path runDirectory = existingRunDirectory(runId);
        if (runDirectory == null) {
            problem(exchange, 404, "RUN_NOT_FOUND", "CSV-first enrichment run was not found");
            return;
        }

        Path artifact = runDirectory.resolve(ARTIFACT_NAME).normalize();
        if (!Files.isRegularFile(artifact)) {
            problem(exchange, 404, "CUSTOMER_ASSET_BUNDLE_NOT_FOUND",
                    "No customer asset bundle has been saved for this run");
            return;
        }

        byte[] bytes = Files.readAllBytes(artifact);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=utf-8");
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("Content-Disposition", "inline; filename=\"" + ARTIFACT_NAME + "\"");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private void write(HttpExchange exchange, UUID runId) throws IOException {
        Path runDirectory = existingRunDirectory(runId);
        if (runDirectory == null) {
            problem(exchange, 404, "RUN_NOT_FOUND", "CSV-first enrichment run was not found");
            return;
        }

        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isJsonContentType(contentType)) {
            problem(exchange, 415, "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be application/json");
            return;
        }

        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (contentLength > maximumUploadBytes) {
            problem(exchange, 413, "UPLOAD_TOO_LARGE",
                    "Customer asset bundle exceeds the configured upload limit");
            return;
        }

        Path artifact = runDirectory.resolve(ARTIFACT_NAME).normalize();
        Path staged = Files.createTempFile(runDirectory, ".customer-assets-", ".json.tmp");
        long bytesWritten;
        try {
            try (InputStream input = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(staged)) {
                bytesWritten = copyBounded(input, output, maximumUploadBytes);
            }
            if (bytesWritten == 0) {
                Files.deleteIfExists(staged);
                problem(exchange, 400, "EMPTY_BUNDLE", "Customer asset bundle must not be empty");
                return;
            }
            replaceAtomically(staged, artifact);
        } catch (UploadTooLargeException exception) {
            Files.deleteIfExists(staged);
            problem(exchange, 413, "UPLOAD_TOO_LARGE",
                    "Customer asset bundle exceeds the configured upload limit");
            return;
        } catch (IOException exception) {
            Files.deleteIfExists(staged);
            throw exception;
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "SAVED");
        response.put("runId", runId.toString());
        response.put("artifact", ROOT + "/" + runId);
        response.put("analysis", ROOT + "/" + runId + "/analyses");
        response.put("fileName", ARTIFACT_NAME);
        response.put("bytes", bytesWritten);
        response.put("semantics", "EXACT_CUSTOMER_DECLARED_BUNDLE_NO_INFERENCE");
        sendJson(exchange, 200, response);
    }

    private void analyzeSaved(HttpExchange exchange, UUID runId) throws IOException {
        Path runDirectory = existingRunDirectory(runId);
        if (runDirectory == null) {
            problem(exchange, 404, "RUN_NOT_FOUND", "CSV-first enrichment run was not found");
            return;
        }
        Path enriched = runDirectory.resolve("enriched.csv").normalize();
        if (!Files.isRegularFile(enriched) || Files.isSymbolicLink(enriched)) {
            problem(exchange, 404, "RUN_NOT_FOUND", "CSV-first enriched CSV was not found");
            return;
        }
        Path savedBundle = runDirectory.resolve(ARTIFACT_NAME).normalize();
        if (!Files.isRegularFile(savedBundle) || Files.isSymbolicLink(savedBundle)) {
            problem(exchange, 409, "CUSTOMER_ASSET_BUNDLE_REQUIRED",
                    "Save the customer asset bundle before creating contextual analysis");
            return;
        }
        if (!regularScript(analysisScript) || !regularScript(admissionScript)) {
            problem(exchange, 503, "CSV_FIRST_CONTEXTUAL_ANALYSIS_UNAVAILABLE",
                    "CSV-first contextual-analysis scripts are unavailable; configure RBVM_REPOSITORY_ROOT");
            return;
        }

        UUID analysisId = UUID.randomUUID();
        Path analyses = runDirectory.resolve("analyses").normalize();
        Path analysisDirectory = analyses.resolve(analysisId.toString()).normalize();
        if (!analyses.startsWith(runDirectory) || !analysisDirectory.startsWith(analyses)) {
            throw new IOException("invalid contextual analysis directory");
        }
        Files.createDirectories(analysisDirectory);
        Path bundle = analysisDirectory.resolve("customer-bundle.json");
        Path analysis = analysisDirectory.resolve("analysis.csv");
        Path summary = analysisDirectory.resolve("analysis-summary.json");
        Path admission = analysisDirectory.resolve("method-admission.json");
        Path analysisLog = analysisDirectory.resolve("analysis-process.log");
        Path admissionLog = analysisDirectory.resolve("admission-process.log");

        try {
            Files.copy(savedBundle, bundle);

            ProcessOutcome analysisOutcome = runProcess(new ProcessBuilder(
                    python,
                    analysisScript.toString(),
                    enriched.toString(),
                    analysis.toString(),
                    summary.toString(),
                    "--customer-bundle", bundle.toString()
            ), analysisLog);
            if (analysisOutcome.interrupted()) {
                deleteTree(analysisDirectory);
                problem(exchange, 503, "CSV_FIRST_CONTEXTUAL_ANALYSIS_INTERRUPTED",
                        "Contextual analysis was interrupted");
                return;
            }
            if (analysisOutcome.timedOut()) {
                deleteTree(analysisDirectory);
                problem(exchange, 504, "CSV_FIRST_CONTEXTUAL_ANALYSIS_TIMEOUT",
                        "Contextual analysis exceeded the execution limit");
                return;
            }
            if (!analysisOutcome.success()
                    || !Files.isRegularFile(analysis)
                    || !Files.isRegularFile(summary)) {
                String diagnostic = boundedDiagnostic(analysisLog);
                deleteTree(analysisDirectory);
                problem(exchange, 422, "CSV_FIRST_CONTEXTUAL_ANALYSIS_FAILED",
                        diagnostic.isBlank() ? "Saved customer context could not be analyzed" : diagnostic);
                return;
            }
            Files.deleteIfExists(analysisLog);

            ProcessOutcome admissionOutcome = runProcess(new ProcessBuilder(
                    python,
                    admissionScript.toString(),
                    analysis.toString(),
                    admission.toString()
            ), admissionLog);
            if (admissionOutcome.interrupted()) {
                deleteTree(analysisDirectory);
                problem(exchange, 503, "CSV_FIRST_METHOD_ADMISSION_INTERRUPTED",
                        "Risk-method admission was interrupted");
                return;
            }
            if (admissionOutcome.timedOut()) {
                deleteTree(analysisDirectory);
                problem(exchange, 504, "CSV_FIRST_METHOD_ADMISSION_TIMEOUT",
                        "Risk-method admission exceeded the execution limit");
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
        } catch (IOException exception) {
            deleteTree(analysisDirectory);
            throw exception;
        }

        String analysisRoot = "/api/v1/csv-first-enrichments/" + runId
                + "/analyses/" + analysisId;
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("contractId", CsvFirstEnrichmentHttpHandler.ANALYSIS_CONTRACT_ID);
        response.put("status", "COMPLETE");
        response.put("scope", "INPUT_CSV_PLUS_SAVED_CUSTOMER_DECLARED_CONTEXT");
        response.put("databaseStateUsed", false);
        response.put("runId", runId.toString());
        response.put("analysisId", analysisId.toString());
        response.put("customerBundleSource", "SAVED_RUN_BUNDLE");
        response.put("immutable", true);
        response.put("customerBundle", analysisRoot + "/customer-bundle");
        response.put("analysisCsv", analysisRoot + "/csv");
        response.put("analysisSummary", analysisRoot + "/summary");
        response.put("methodAdmission", analysisRoot + "/method-admission");
        response.put("priority", "/api/v1/csv-first-priorities/" + runId + "/" + analysisId);
        response.put("outputSemantics", "CONTEXTUAL_TECHNICAL_SEVERITY_PLUS_INDEPENDENT_EVIDENCE");
        response.put("organizationalRisk", "NON_COMPUTABLE");
        sendJson(exchange, 201, response);
    }

    private UUID parseRunId(HttpExchange exchange, String value) throws IOException {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            problem(exchange, 400, "INVALID_RUN_ID", "runId must be a UUID");
            return null;
        }
    }

    private Path existingRunDirectory(UUID runId) {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        if (!run.startsWith(runs) || !Files.isDirectory(run)) return null;
        return run;
    }

    private ProcessOutcome runProcess(ProcessBuilder builder, Path log) throws IOException {
        builder.directory(repositoryRoot.toFile());
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

    private void requireRole(HttpExchange exchange, ApiRole role) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        Optional<AuthPrincipal> principal = authenticator.authenticate(authorization);
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
        }
    }

    private static boolean regularScript(Path script) {
        return Files.isRegularFile(script) && !Files.isSymbolicLink(script);
    }

    private static String boundedDiagnostic(Path log) throws IOException {
        byte[] output = Files.isRegularFile(log) ? Files.readAllBytes(log) : new byte[0];
        return new String(
                output,
                0,
                Math.min(output.length, MAX_PROCESS_OUTPUT_BYTES),
                StandardCharsets.UTF_8
        ).trim();
    }

    private static boolean isJsonContentType(String value) {
        if (value == null) return false;
        String normalized = value.toLowerCase(Locale.ROOT).split(";", 2)[0].trim();
        return "application/json".equals(normalized);
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

    private static long copyBounded(InputStream input, OutputStream output, long maximumBytes)
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
        return total;
    }

    private static void replaceAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(source, target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void deleteTree(Path directory) {
        if (directory == null || !Files.exists(directory)) return;
        try (var paths = Files.walk(directory)) {
            paths.sorted((left, right) -> right.getNameCount() - left.getNameCount())
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (IOException ignored) {
                            // Best effort cleanup of an unpublished analysis.
                        }
                    });
        } catch (IOException ignored) {
            // Best effort cleanup of an unpublished analysis.
        }
    }

    private static void problem(HttpExchange exchange, int status, String code, String detail)
            throws IOException {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("type", "about:blank");
        value.put("title", code);
        value.put("status", status);
        value.put("detail", detail);
        sendJson(exchange, status, value);
    }

    private static void sendJson(HttpExchange exchange, int status, Map<String, ?> value)
            throws IOException {
        byte[] bytes = JsonOutput.object(value).getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=utf-8");
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private record ProcessOutcome(boolean success, boolean timedOut, boolean interrupted) {
    }

    private static final class UploadTooLargeException extends IOException {
        private static final long serialVersionUID = 1L;
    }
}
