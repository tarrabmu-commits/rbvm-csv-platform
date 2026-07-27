package io.rbvm.csv;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public final class WazuhCsvAnalyzer {
    private static final Pattern CVE_PATTERN = Pattern.compile("(?i)^CVE-\\d{4}-\\d{4,}$");
    private static final int MAX_ISSUE_SAMPLES = 100;
    private static final List<String> SEMANTIC_HEADERS = CsvContractV1.HEADERS;

    private final String sourceProfileId;

    public WazuhCsvAnalyzer(String sourceProfileId) {
        if (sourceProfileId == null || sourceProfileId.isBlank()) {
            throw new IllegalArgumentException("sourceProfileId is required");
        }
        this.sourceProfileId = sourceProfileId.trim();
    }

    public AnalysisReport analyze(Path path, int previewLimit) throws IOException {
        return analyze(path, previewLimit, ignored -> { });
    }

    public AnalysisReport analyze(Path path, int previewLimit, ObservationSink observationSink)
            throws IOException {
        if (previewLimit < 0 || previewLimit > 100) {
            throw new IllegalArgumentException("previewLimit must be between 0 and 100");
        }
        if (observationSink == null) {
            throw new IllegalArgumentException("observationSink is required");
        }

        long fileSize = Files.size(path);
        String fileHash = sha256File(path);
        try {
            ensureStrictUtf8(path);
        } catch (CharacterCodingException exception) {
            throw new CsvContractException("CSV must be valid UTF-8", exception);
        }

        long logicalRows = 0;
        long acceptedRows = 0;
        long deduplicatedRows = 0;
        long quarantinedRows = 0;
        long embeddedNewlineValues = 0;
        long rowsWithoutHttpReferences = 0;
        Instant minimumDetectedAt = null;
        Instant maximumDetectedAt = null;

        Set<String> agents = new HashSet<>();
        Set<String> cves = new HashSet<>();
        Set<String> products = new HashSet<>();
        Set<String> rowFingerprints = new HashSet<>();
        Map<String, ExposureAccumulator> exposures = new HashMap<>();
        Map<String, Set<String>> productsPerCase = new HashMap<>();
        Map<CsvSeverity, Long> severity = new EnumMap<>(CsvSeverity.class);
        Map<String, Integer> maxLengths = new LinkedHashMap<>();
        List<ValidationIssue> issues = new ArrayList<>();
        List<Map<String, Object>> preview = new ArrayList<>();
        CsvContractV1.HeaderMapping mapping;

        for (CsvSeverity value : CsvSeverity.values()) {
            severity.put(value, 0L);
        }
        for (String header : SEMANTIC_HEADERS) {
            maxLengths.put(header, 0);
        }

        try (InputStream input = new BufferedInputStream(Files.newInputStream(path));
             BufferedReader decoded = new BufferedReader(new InputStreamReader(input, strictUtf8Decoder()));
             Rfc4180CsvReader csv = new Rfc4180CsvReader(decoded)) {

            List<String> rawHeaders = csv.readRow();
            if (rawHeaders == null) {
                throw new CsvContractException("CSV file is empty");
            }
            mapping = CsvContractV1.mapHeaders(rawHeaders);

            List<String> row;
            while ((row = csv.readRow()) != null) {
                logicalRows++;
                long sourceRowNumber = logicalRows + 1;
                List<String> currentRow = row;

                if (currentRow.size() != rawHeaders.size()) {
                    quarantinedRows++;
                    addIssue(issues, new ValidationIssue(sourceRowNumber, ValidationIssue.Level.ERROR,
                            "COLUMN_COUNT_MISMATCH",
                            "Expected " + rawHeaders.size() + " columns but found " + currentRow.size()));
                    continue;
                }

                updateLengthsAndNewlines(mapping, currentRow, maxLengths);
                embeddedNewlineValues += countNewlineValues(mapping, currentRow);

                List<String> missingRequired = CsvContractV1.ROW_REQUIRED.stream()
                        .filter(header -> mapping.value(currentRow, header).trim().isEmpty())
                        .toList();
                if (!missingRequired.isEmpty()) {
                    quarantinedRows++;
                    addIssue(issues, new ValidationIssue(sourceRowNumber, ValidationIssue.Level.ERROR,
                            "MISSING_REQUIRED_VALUE", "Missing values: " + missingRequired));
                    continue;
                }

                String cve = mapping.value(currentRow, "CVE_ID").trim().toUpperCase(Locale.ROOT);
                if (!CVE_PATTERN.matcher(cve).matches()) {
                    quarantinedRows++;
                    addIssue(issues, new ValidationIssue(sourceRowNumber, ValidationIssue.Level.ERROR,
                            "INVALID_CVE", "Invalid CVE identifier: " + cve));
                    continue;
                }

                Instant detectedAt;
                try {
                    detectedAt = Instant.parse(mapping.value(currentRow, "Detected_At").trim());
                } catch (DateTimeParseException exception) {
                    quarantinedRows++;
                    addIssue(issues, new ValidationIssue(sourceRowNumber, ValidationIssue.Level.ERROR,
                            "INVALID_DETECTED_AT", "Detected_At must be ISO-8601 with timezone"));
                    continue;
                }

                CsvSeverity.ParseResult severityResult = CsvSeverity.parse(mapping.value(currentRow, "Severity"));
                if (!severityResult.recognized()) {
                    addIssue(issues, new ValidationIssue(sourceRowNumber, ValidationIssue.Level.WARNING,
                            "UNRECOGNIZED_SEVERITY",
                            "Mapped source severity to UNKNOWN: " + mapping.value(currentRow, "Severity")));
                }

                String rowFingerprint = fingerprint(mapping, currentRow);
                if (!rowFingerprints.add(rowFingerprint)) {
                    deduplicatedRows++;
                    continue;
                }

                acceptedRows++;
                String agentRaw = mapping.value(currentRow, "Agent").trim();
                String productRaw = mapping.value(currentRow, "Affected_Product").trim();
                String agent = normalizeKey(agentRaw);
                String product = normalizeKey(productRaw);
                String exposureKey = compositeKey(sourceProfileId, agent, cve, product);
                String caseKey = compositeKey(sourceProfileId, agent, cve);

                agents.add(agent);
                cves.add(cve);
                products.add(product);
                severity.compute(severityResult.value(), (ignored, count) -> count + 1);
                exposures.computeIfAbsent(exposureKey, ignored -> new ExposureAccumulator())
                        .observe(severityResult.value());
                productsPerCase.computeIfAbsent(caseKey, ignored -> new LinkedHashSet<>()).add(product);

                if (minimumDetectedAt == null || detectedAt.isBefore(minimumDetectedAt)) {
                    minimumDetectedAt = detectedAt;
                }
                if (maximumDetectedAt == null || detectedAt.isAfter(maximumDetectedAt)) {
                    maximumDetectedAt = detectedAt;
                }

                String references = mapping.value(currentRow, "References");
                if (!containsHttpReference(references)) {
                    rowsWithoutHttpReferences++;
                }

                observationSink.accept(new WazuhObservation(
                        sourceRowNumber,
                        sourceProfileId,
                        rowFingerprint,
                        agentRaw,
                        agent,
                        cve,
                        severityResult.value(),
                        severityResult.recognized(),
                        mapping.value(currentRow, "CVE_Description"),
                        productRaw,
                        product,
                        references,
                        mapping.value(currentRow, "OS_name").trim(),
                        detectedAt
                ));

                if (preview.size() < previewLimit) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("rowNumber", sourceRowNumber);
                    item.put("agent", agentRaw);
                    item.put("cve", cve);
                    item.put("severity", severityResult.value().name());
                    item.put("affectedProduct", productRaw);
                    item.put("osName", mapping.value(currentRow, "OS_name").trim());
                    item.put("detectedAt", detectedAt.toString());
                    item.put("observationFingerprint", rowFingerprint);
                    preview.add(item);
                }
            }
        } catch (CharacterCodingException exception) {
            throw new CsvContractException("CSV must be valid UTF-8", exception);
        }

        long repeatedGroups = exposures.values().stream().filter(value -> value.observations > 1).count();
        long repeatedObservations = exposures.values().stream()
                .mapToLong(value -> Math.max(0, value.observations - 1)).sum();
        long severityChanges = exposures.values().stream().filter(value -> value.severities.size() > 1).count();
        long multipleProductCases = productsPerCase.values().stream().filter(value -> value.size() > 1).count();
        int maximumProducts = productsPerCase.values().stream().mapToInt(Set::size).max().orElse(0);

        Map<String, Long> severityOutput = new LinkedHashMap<>();
        for (CsvSeverity value : CsvSeverity.values()) {
            severityOutput.put(value.name(), severity.get(value));
        }

        return new AnalysisReport(
                CsvContractV1.ID,
                "POSITIVE_OBSERVATION_EXPORT",
                fileSize,
                fileHash,
                mapping.headers(),
                mapping.additionalHeaders(),
                logicalRows,
                acceptedRows,
                deduplicatedRows,
                quarantinedRows,
                agents.size(),
                cves.size(),
                products.size(),
                exposures.size(),
                repeatedGroups,
                repeatedObservations,
                severityChanges,
                productsPerCase.size(),
                multipleProductCases,
                maximumProducts,
                Collections.unmodifiableMap(new LinkedHashMap<>(severityOutput)),
                minimumDetectedAt,
                maximumDetectedAt,
                Collections.unmodifiableMap(new LinkedHashMap<>(maxLengths)),
                embeddedNewlineValues,
                rowsWithoutHttpReferences,
                List.copyOf(issues),
                List.copyOf(preview)
        );
    }

    private static void updateLengthsAndNewlines(
            CsvContractV1.HeaderMapping mapping,
            List<String> row,
            Map<String, Integer> maxLengths
    ) {
        for (String header : SEMANTIC_HEADERS) {
            int length = mapping.value(row, header).length();
            maxLengths.compute(header, (ignored, current) -> Math.max(current, length));
        }
    }

    private static long countNewlineValues(CsvContractV1.HeaderMapping mapping, List<String> row) {
        return SEMANTIC_HEADERS.stream()
                .map(header -> mapping.value(row, header))
                .filter(value -> value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0)
                .count();
    }

    private static boolean containsHttpReference(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        for (String token : value.split(",\\s*")) {
            try {
                URI uri = URI.create(token.trim());
                if ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme())) {
                    return true;
                }
            } catch (IllegalArgumentException ignored) {
                // The caller only needs to know whether at least one HTTP(S) reference exists.
            }
        }
        return false;
    }

    private static String normalizeKey(String value) {
        return Normalizer.normalize(value.trim(), Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }

    private static String compositeKey(String... values) {
        return String.join("\u001F", values);
    }

    private static String fingerprint(CsvContractV1.HeaderMapping mapping, List<String> row) {
        MessageDigest digest = sha256Digest();
        updateFingerprint(digest, CsvContractV1.ID);
        List<String> orderedHeaders = new ArrayList<>(SEMANTIC_HEADERS);
        mapping.additionalHeaders().stream().sorted().forEach(orderedHeaders::add);
        for (String header : orderedHeaders) {
            updateFingerprint(digest, header);
            String value = mapping.value(row, header);
            updateFingerprint(digest, value);
        }
        return hex(digest.digest());
    }

    private static void updateFingerprint(MessageDigest digest, String value) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
            digest.update(bytes);
    }

    private static String sha256File(Path path) throws IOException {
        MessageDigest digest = sha256Digest();
        try (InputStream input = new BufferedInputStream(Files.newInputStream(path));
             DigestInputStream hashing = new DigestInputStream(input, digest)) {
            byte[] buffer = new byte[64 * 1024];
            while (hashing.read(buffer) != -1) {
                // DigestInputStream updates the digest.
            }
        }
        return hex(digest.digest());
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format("%02x", value));
        }
        return result.toString();
    }

    private static java.nio.charset.CharsetDecoder strictUtf8Decoder() {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
    }

    private static void ensureStrictUtf8(Path path) throws IOException {
        try (InputStream input = Files.newInputStream(path);
             InputStreamReader reader = new InputStreamReader(input, strictUtf8Decoder())) {
            char[] buffer = new char[64 * 1024];
            while (reader.read(buffer) != -1) {
                // A decoding exception is the validation result.
            }
        }
    }

    private static void addIssue(List<ValidationIssue> issues, ValidationIssue issue) {
        if (issues.size() < MAX_ISSUE_SAMPLES) {
            issues.add(issue);
        }
    }

    private static final class ExposureAccumulator {
        private long observations;
        private final Set<CsvSeverity> severities = new HashSet<>();

        private void observe(CsvSeverity severity) {
            observations++;
            severities.add(severity);
        }
    }
}
