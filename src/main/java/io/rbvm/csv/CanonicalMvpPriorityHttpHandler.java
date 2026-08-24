package io.rbvm.csv;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import io.rbvm.postgres.CanonicalMvpPriorityStore;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Materializes immutable CSV-first Pareto priority onto exact canonical Findings. */
public final class CanonicalMvpPriorityHttpHandler implements HttpHandler {
    public static final String CONTRACT_ID = "CANONICAL_MVP_PRIORITY_MATERIALIZATION_HTTP_V1";
    private static final String ROOT = "/api/v1/canonical-mvp-priorities";
    private static final Pattern MATERIALIZE_PATH = Pattern.compile(
            "^/api/v1/canonical-mvp-priorities/([0-9a-fA-F-]{36})/([0-9a-fA-F-]{36})/([0-9a-fA-F-]{36})$");
    private static final Set<String> REQUIRED = Set.of(
            "KEV_Listed", "Internet_Facing", "Asset_Criticality", "EPSS_Probability",
            "CVSS4_Context_Score", "RBVM_MVP_Priority_Status", "RBVM_MVP_Priority_Front",
            "RBVM_MVP_Priority_Dominated_By", "RBVM_MVP_Priority_Dominates",
            "RBVM_MVP_Priority_Blockers", "RBVM_MVP_Priority_Explanation",
            "RBVM_MVP_Priority_Method_SHA256");

    private final Path dataDirectory;
    private final Optional<CanonicalMvpPriorityStore> store;
    private final ApiKeyAuthenticator authenticator;

    public CanonicalMvpPriorityHttpHandler(
            Path dataDirectory,
            Optional<CanonicalMvpPriorityStore> store,
            ApiKeyAuthenticator authenticator
    ) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        this.store = Objects.requireNonNull(store, "store");
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
            String path = exchange.getRequestURI().getPath();
            Matcher matcher = MATERIALIZE_PATH.matcher(path);
            if (!matcher.matches()) {
                problem(exchange, 404, "NOT_FOUND", "The requested canonical MVP-priority route does not exist");
                return;
            }
            requireRole(exchange, ApiRole.OPERATOR);
            if (!"POST".equals(method)) {
                exchange.getResponseHeaders().set("Allow", "POST");
                problem(exchange, 405, "METHOD_NOT_ALLOWED", "HTTP method is not allowed for this resource");
                return;
            }
            UUID importId = parseId(exchange, matcher.group(1), "INVALID_IMPORT_ID");
            if (importId == null) return;
            UUID runId = parseId(exchange, matcher.group(2), "INVALID_RUN_ID");
            if (runId == null) return;
            UUID analysisId = parseId(exchange, matcher.group(3), "INVALID_ANALYSIS_ID");
            if (analysisId == null) return;
            materialize(exchange, importId, runId, analysisId);
        } catch (SecurityException exception) {
            problem(exchange, 403, "FORBIDDEN", "The request is not authorized");
        } catch (CanonicalMvpPriorityStore.NotFoundException exception) {
            problem(exchange, 404, "CANONICAL_IMPORT_NOT_FOUND", exception.getMessage());
        } catch (CanonicalMvpPriorityStore.ConflictException exception) {
            problem(exchange, 409, "CANONICAL_PRIORITY_CONFLICT", exception.getMessage());
        } catch (CsvContractException | IllegalArgumentException exception) {
            problem(exchange, 422, "CANONICAL_PRIORITY_ARTIFACT_REJECTED", exception.getMessage());
        } catch (Exception exception) {
            exception.printStackTrace(System.err);
            problem(exchange, 500, "INTERNAL_ERROR", "Canonical MVP priority could not be materialized");
        } finally {
            exchange.close();
        }
    }

    private void materialize(HttpExchange exchange, UUID importId, UUID runId, UUID analysisId)
            throws IOException {
        CanonicalMvpPriorityStore persistence = store.orElse(null);
        if (persistence == null) {
            problem(exchange, 503, "CANONICAL_MVP_PRIORITY_PERSISTENCE_UNAVAILABLE",
                    "Canonical MVP priority requires PostgreSQL schema version 29 or newer");
            return;
        }

        Path run = runDirectory(runId);
        Path source = regular(run.resolve("input.csv"), run, "CSV-first source artifact does not exist");
        Path priorityRoot = run.resolve("analyses").resolve(analysisId.toString()).resolve("priority")
                .resolve(CanonicalMvpPriorityStore.METHOD_SHA256).normalize();
        if (!priorityRoot.startsWith(run)) throw new IOException("invalid priority artifact path");
        Path priorityCsv = regular(
                priorityRoot.resolve("priority.csv"), priorityRoot,
                "Immutable MVP priority artifact does not exist; derive priority before canonical materialization");
        regular(priorityRoot.resolve("priority-report.json"), priorityRoot,
                "Immutable MVP priority report does not exist");

        String sourceSha = sha256(source);
        String prioritySha = sha256(priorityCsv);
        List<CanonicalMvpPriorityStore.PriorityRow> rows = readPriorityRows(priorityCsv);
        CanonicalMvpPriorityStore.MaterializationResult result = persistence.materialize(
                importId, runId, analysisId, sourceSha, prioritySha, rows, Instant.now());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("contractId", CONTRACT_ID);
        response.put("status", "COMPLETE");
        response.put("importId", importId.toString());
        response.put("runId", runId.toString());
        response.put("analysisId", analysisId.toString());
        response.put("methodId", CanonicalMvpPriorityStore.METHOD_ID);
        response.put("methodSha256", CanonicalMvpPriorityStore.METHOD_SHA256);
        response.put("classification", "RBVM_POLICY");
        response.put("prioritySemantics", "RELATIVE_TREATMENT_PRIORITY_PARETO_FRONT_WITHIN_INPUT_SET");
        response.put("canonicalFindings", result.canonicalFindings());
        response.put("mappedSourceRows", result.mappedSourceRows());
        response.put("insertedResults", result.insertedResults());
        response.put("replayedResults", result.replayedResults());
        response.put("sourceCsvSha256", result.sourceCsvSha256());
        response.put("priorityCsvSha256", result.priorityCsvSha256());
        response.put("association", "EXACT_IMPORT_SOURCE_ROW_TO_OBSERVATION_TO_EXPOSURE_ONLY");
        response.put("organizationalRisk", "NON_COMPUTABLE");
        sendJson(exchange, result.insertedResults() > 0 ? 201 : 200, response);
    }

    private List<CanonicalMvpPriorityStore.PriorityRow> readPriorityRows(Path path) throws IOException {
        List<CanonicalMvpPriorityStore.PriorityRow> output = new ArrayList<>();
        try (BufferedReader text = Files.newBufferedReader(path, StandardCharsets.UTF_8);
             Rfc4180CsvReader reader = new Rfc4180CsvReader(text)) {
            List<String> headers = reader.readRow();
            if (headers == null) throw new CsvContractException("Priority CSV is empty");
            List<String> normalizedHeaders = new ArrayList<>(headers);
            if (!normalizedHeaders.isEmpty()) {
                normalizedHeaders.set(0, normalizedHeaders.get(0).replace("\uFEFF", ""));
            }
            Map<String, Integer> index = new HashMap<>();
            for (int i = 0; i < normalizedHeaders.size(); i++) {
                String name = normalizedHeaders.get(i);
                if (index.put(name, i) != null) throw new CsvContractException("Duplicate priority CSV header: " + name);
            }
            for (String required : REQUIRED) {
                if (!index.containsKey(required)) throw new CsvContractException("Priority CSV missing column: " + required);
            }
            long sourceRow = 2;
            List<String> values;
            while ((values = reader.readRow()) != null) {
                if (values.size() != normalizedHeaders.size()) {
                    throw new CsvContractException("Priority CSV column count mismatch at source row " + sourceRow);
                }
                output.add(priorityRow(index, values, sourceRow));
                sourceRow++;
            }
        }
        if (output.isEmpty()) throw new CsvContractException("Priority CSV contains no finding rows");
        return List.copyOf(output);
    }

    private static CanonicalMvpPriorityStore.PriorityRow priorityRow(
            Map<String, Integer> index,
            List<String> values,
            long sourceRow
    ) {
        String status = value(index, values, "RBVM_MVP_Priority_Status").trim();
        if (!status.equals("RANKED_RELATIVE_ONLY")
                && !status.equals("UNRANKABLE_MISSING_EVIDENCE")) {
            throw new IllegalArgumentException("Invalid MVP priority status at source row " + sourceRow);
        }
        String methodSha = value(index, values, "RBVM_MVP_Priority_Method_SHA256").trim();
        if (!CanonicalMvpPriorityStore.METHOD_SHA256.equals(methodSha)) {
            throw new IllegalArgumentException("MVP priority method SHA mismatch at source row " + sourceRow);
        }
        Integer front = integerOrNull(value(index, values, "RBVM_MVP_Priority_Front"), sourceRow);
        Long dominatedBy = longOrNull(value(index, values, "RBVM_MVP_Priority_Dominated_By"), sourceRow);
        Long dominates = longOrNull(value(index, values, "RBVM_MVP_Priority_Dominates"), sourceRow);
        String blockers = value(index, values, "RBVM_MVP_Priority_Blockers").trim();
        String explanation = value(index, values, "RBVM_MVP_Priority_Explanation").trim();
        if (explanation.isEmpty()) throw new IllegalArgumentException("Missing priority explanation at source row " + sourceRow);
        if (status.equals("RANKED_RELATIVE_ONLY")) {
            if (front == null || front <= 0 || dominatedBy == null || dominates == null || !blockers.isEmpty()) {
                throw new IllegalArgumentException("Invalid ranked priority fields at source row " + sourceRow);
            }
        } else if (front != null || dominatedBy != null || dominates != null || blockers.isEmpty()) {
            throw new IllegalArgumentException("Invalid unrankable priority fields at source row " + sourceRow);
        }
        return new CanonicalMvpPriorityStore.PriorityRow(
                sourceRow,
                status,
                front,
                dominatedBy,
                dominates,
                blockers,
                explanation,
                methodSha,
                boolOrNull(value(index, values, "KEV_Listed"), sourceRow),
                enumOrNull(value(index, values, "Internet_Facing"), Set.of("YES", "NO"), sourceRow),
                enumOrNull(value(index, values, "Asset_Criticality"),
                        Set.of("LOW", "MODERATE", "HIGH", "MISSION_CRITICAL"), sourceRow),
                decimalOrNull(value(index, values, "EPSS_Probability"), BigDecimal.ZERO, BigDecimal.ONE, sourceRow),
                decimalOrNull(value(index, values, "CVSS4_Context_Score"), BigDecimal.ZERO, BigDecimal.TEN, sourceRow)
        );
    }

    private Path runDirectory(UUID runId) throws IOException {
        Path runs = dataDirectory.resolve("csv-first-enrichments").normalize();
        Path run = runs.resolve(runId.toString()).normalize();
        if (!run.startsWith(runs)) throw new IOException("invalid CSV-first run path");
        return run;
    }

    private static Path regular(Path path, Path parent, String message) throws IOException {
        Path normalized = path.normalize();
        if (!normalized.startsWith(parent.normalize())
                || !Files.isRegularFile(normalized) || Files.isSymbolicLink(normalized)) {
            throw new CanonicalMvpPriorityStore.NotFoundException(message);
        }
        return normalized;
    }

    private static String value(Map<String, Integer> index, List<String> values, String name) {
        return values.get(index.get(name));
    }

    private static Integer integerOrNull(String raw, long row) {
        String value = raw.trim();
        if (value.isEmpty()) return null;
        try { return Integer.valueOf(value); }
        catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Invalid integer at source row " + row, exception);
        }
    }

    private static Long longOrNull(String raw, long row) {
        String value = raw.trim();
        if (value.isEmpty()) return null;
        try {
            long parsed = Long.parseLong(value);
            if (parsed < 0) throw new NumberFormatException("negative");
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Invalid non-negative count at source row " + row, exception);
        }
    }

    private static Boolean boolOrNull(String raw, long row) {
        String value = raw.trim().toLowerCase(Locale.ROOT);
        if (value.isEmpty()) return null;
        if (Set.of("true", "1", "yes", "listed").contains(value)) return true;
        if (Set.of("false", "0", "no", "not_listed", "not listed").contains(value)) return false;
        throw new IllegalArgumentException("Invalid KEV state at source row " + row);
    }

    private static String enumOrNull(String raw, Set<String> allowed, long row) {
        String value = raw.trim().toUpperCase(Locale.ROOT);
        if (value.isEmpty() || value.equals("UNKNOWN")) return null;
        if (!allowed.contains(value)) throw new IllegalArgumentException("Invalid categorical input at source row " + row);
        return value;
    }

    private static BigDecimal decimalOrNull(String raw, BigDecimal minimum, BigDecimal maximum, long row) {
        String value = raw.trim();
        if (value.isEmpty()) return null;
        try {
            BigDecimal parsed = new BigDecimal(value);
            if (parsed.compareTo(minimum) < 0 || parsed.compareTo(maximum) > 0) {
                throw new NumberFormatException("outside range");
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Invalid numeric priority input at source row " + row, exception);
        }
    }

    private static String sha256(Path path) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (var input = Files.newInputStream(path)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    if (read > 0) digest.update(buffer, 0, read);
                }
            }
            return java.util.HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required", exception);
        }
    }

    private UUID parseId(HttpExchange exchange, String value, String code) throws IOException {
        try { return UUID.fromString(value); }
        catch (IllegalArgumentException exception) {
            problem(exchange, 400, code, "Invalid identifier");
            return null;
        }
    }

    private void requireRole(HttpExchange exchange, ApiRole role) {
        Optional<AuthPrincipal> principal = authenticator.authenticate(
                exchange.getRequestHeaders().getFirst("Authorization"));
        if (principal.isEmpty() || !principal.get().role().permits(role)) {
            throw new SecurityException("insufficient role");
        }
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
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream body = exchange.getResponseBody()) { body.write(bytes); }
    }
}
