package io.rbvm.csv;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.rbvm.postgres.CisaKevImporter;
import io.rbvm.postgres.EpssImporter;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.IOException;
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
 * Explicit operator handoff from one CSV-first run into the existing canonical
 * FIRST EPSS and CISA KEV evidence stores.
 *
 * <p>This endpoint deliberately re-acquires the official canonical source artifacts used by
 * EPSS_CSV_V1 and CISA_KEV_CSV_V1. It does not relabel the CSV-first EPSS API response as the
 * pinned FIRST daily feed, does not convert CVSS v4 to v3.1, and does not calculate risk.</p>
 */
public final class CsvFirstCanonicalEvidenceHttpHandler implements HttpHandler {
    public static final String CONTRACT_ID = "CSV_FIRST_CANONICAL_PUBLIC_EVIDENCE_HTTP_V1";
    private static final Pattern PATH = Pattern.compile(
            "^/api/v1/csv-first-canonical-evidence/([0-9a-fA-F-]{36})$");
    private static final Duration PROCESS_TIMEOUT = Duration.ofMinutes(10);

    private final Path dataDirectory;
    private final Path repositoryRoot;
    private final String python;
    private final Optional<EpssImporter> epssImporter;
    private final Optional<CisaKevImporter> kevImporter;
    private final ApiKeyAuthenticator authenticator;

    public CsvFirstCanonicalEvidenceHttpHandler(
            Path dataDirectory,
            Optional<EpssImporter> epssImporter,
            Optional<CisaKevImporter> kevImporter,
            ApiKeyAuthenticator authenticator
    ) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        this.epssImporter = Objects.requireNonNull(epssImporter, "epssImporter");
        this.kevImporter = Objects.requireNonNull(kevImporter, "kevImporter");
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        this.repositoryRoot = Path.of(System.getenv().getOrDefault("RBVM_REPOSITORY_ROOT", "."))
                .toAbsolutePath().normalize();
        this.python = System.getenv().getOrDefault("RBVM_PYTHON", "python3");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            Matcher matcher = PATH.matcher(exchange.getRequestURI().getPath());
            if (!matcher.matches()) {
                problem(exchange, 404, "NOT_FOUND", "The requested canonical-evidence route does not exist");
                return;
            }
            requireRole(exchange, ApiRole.OPERATOR);
            if (!"POST".equals(exchange.getRequestMethod().toUpperCase(Locale.ROOT))) {
                exchange.getResponseHeaders().set("Allow", "POST");
                problem(exchange, 405, "METHOD_NOT_ALLOWED", "Use POST for canonical public-evidence handoff");
                return;
            }
            UUID runId = UUID.fromString(matcher.group(1));
            materialize(exchange, runId);
        } catch (IllegalArgumentException exception) {
            problem(exchange, 400, "INVALID_RUN_ID", "Invalid CSV-first enrichment run identifier");
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (Exception exception) {
            exception.printStackTrace(System.err);
            problem(exchange, 500, "INTERNAL_ERROR", "Canonical public-evidence handoff could not be completed");
        } finally {
            exchange.close();
        }
    }

    private void materialize(HttpExchange exchange, UUID runId) throws Exception {
        if (epssImporter.isEmpty() || kevImporter.isEmpty()) {
            problem(exchange, 503, "CANONICAL_EVIDENCE_PERSISTENCE_UNAVAILABLE",
                    "Canonical EPSS/KEV persistence is unavailable in this runtime");
            return;
        }

        Path input = sourcePath(runId);
        if (!Files.isRegularFile(input) || Files.isSymbolicLink(input)) {
            problem(exchange, 404, "RUN_SOURCE_NOT_FOUND", "The original CSV-first source artifact does not exist");
            return;
        }

        Path fetchEpss = script("fetch-first-epss-snapshot.py");
        Path buildEpss = script("build-first-epss-csv.py");
        Path fetchKev = script("fetch-cisa-kev-snapshot.py");
        Path buildKev = script("build-cisa-kev-csv.py");
        for (Path script : new Path[]{fetchEpss, buildEpss, fetchKev, buildKev}) {
            if (!Files.isRegularFile(script) || Files.isSymbolicLink(script)) {
                problem(exchange, 503, "CANONICAL_EVIDENCE_SOURCE_ADAPTER_UNAVAILABLE",
                        "Canonical evidence source adapters are unavailable; configure RBVM_REPOSITORY_ROOT");
                return;
            }
        }

        UUID evidenceId = UUID.randomUUID();
        Path directory = evidenceDirectory(runId, evidenceId);
        Files.createDirectories(directory);
        Path epssSnapshot = directory.resolve("first-epss-snapshot.json");
        Path epssCsv = directory.resolve("epss.csv");
        Path epssReport = directory.resolve("epss-report.json");
        Path kevSnapshot = directory.resolve("cisa-kev-snapshot.json");
        Path kevCsv = directory.resolve("kev.csv");
        Path kevReport = directory.resolve("kev-report.json");

        try {
            runRequired(new ProcessBuilder(python, fetchEpss.toString(), input.toString(), epssSnapshot.toString()),
                    directory.resolve("fetch-epss.log"), "FIRST_EPSS_SOURCE_FAILED");
            runRequired(new ProcessBuilder(python, buildEpss.toString(), epssSnapshot.toString(), epssCsv.toString(),
                            "--report", epssReport.toString()),
                    directory.resolve("build-epss.log"), "FIRST_EPSS_BUILD_FAILED");
            runRequired(new ProcessBuilder(python, fetchKev.toString(), kevSnapshot.toString()),
                    directory.resolve("fetch-kev.log"), "CISA_KEV_SOURCE_FAILED");
            runRequired(new ProcessBuilder(python, buildKev.toString(), input.toString(), kevSnapshot.toString(),
                            kevCsv.toString(), "--report", kevReport.toString()),
                    directory.resolve("build-kev.log"), "CISA_KEV_BUILD_FAILED");

            Map<String, Object> epss = epssImporter.orElseThrow().importFile(epssCsv).toMap();
            Map<String, Object> kev = kevImporter.orElseThrow().importFile(kevCsv).toMap();

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("contractId", CONTRACT_ID);
            response.put("status", "COMPLETE");
            response.put("runId", runId.toString());
            response.put("evidenceId", evidenceId.toString());
            response.put("immutableArtifacts", true);
            response.put("epss", epss);
            response.put("cisaKev", kev);
            response.put("cvssV4", "CONTEXTUAL_ANALYSIS_ARTIFACT_ONLY");
            response.put("cvssV4ToV31Conversion", false);
            response.put("organizationalRisk", "NON_COMPUTABLE");
            response.put("decisionReadiness",
                    "REQUIRES_EXPLICIT_APPLICABILITY_AND_CUSTOMER_CONFIRMED_CONTEXT_ASSOCIATIONS");
            sendJson(exchange, 201, response);
        } catch (ProcessFailure failure) {
            problem(exchange, failure.status, failure.code, failure.getMessage());
        }
    }

    private void runRequired(ProcessBuilder builder, Path log, String code) throws Exception {
        builder.redirectErrorStream(true).redirectOutput(log.toFile());
        Process process = builder.start();
        boolean completed;
        try {
            completed = process.waitFor(PROCESS_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new ProcessFailure(503, code, "Canonical evidence source adapter was interrupted");
        }
        if (!completed) {
            process.destroyForcibly();
            throw new ProcessFailure(504, code, "Canonical evidence source adapter exceeded the execution limit");
        }
        if (process.exitValue() != 0) {
            String diagnostic = Files.isRegularFile(log)
                    ? Files.readString(log, StandardCharsets.UTF_8).trim() : "";
            if (diagnostic.length() > 2000) diagnostic = diagnostic.substring(0, 2000);
            throw new ProcessFailure(422, code,
                    diagnostic.isBlank() ? "Canonical evidence source adapter failed" : diagnostic);
        }
        Files.deleteIfExists(log);
    }

    private Path sourcePath(UUID runId) throws IOException {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        if (!run.startsWith(runs)) throw new IOException("invalid run directory");
        Path source = run.resolve("input.csv").normalize();
        if (!source.startsWith(run)) throw new IOException("invalid source path");
        return source;
    }

    private Path evidenceDirectory(UUID runId, UUID evidenceId) throws IOException {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        Path root = run.resolve("canonical-evidence").normalize();
        Path directory = root.resolve(evidenceId.toString()).normalize();
        if (!run.startsWith(runs) || !root.startsWith(run) || !directory.startsWith(root)) {
            throw new IOException("invalid canonical evidence directory");
        }
        return directory;
    }

    private Path script(String name) {
        return repositoryRoot.resolve("scripts").resolve(name).normalize();
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        Optional<AuthPrincipal> principal = authenticator.authenticate(
                exchange.getRequestHeaders().getFirst("Authorization"));
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
        }
    }

    private static void sendJson(HttpExchange exchange, int status, Map<String, Object> value) throws IOException {
        sendBytes(exchange, status, "application/json; charset=utf-8",
                JsonOutput.object(value).getBytes(StandardCharsets.UTF_8));
    }

    private static void problem(HttpExchange exchange, int status, String code, String detail) throws IOException {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("type", "about:blank");
        value.put("title", code);
        value.put("status", status);
        value.put("detail", detail);
        sendJson(exchange, status, value);
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

    private static final class ProcessFailure extends Exception {
        private static final long serialVersionUID = 1L;
        private final int status;
        private final String code;

        private ProcessFailure(int status, String code, String message) {
            super(message);
            this.status = status;
            this.code = code;
        }
    }
}
