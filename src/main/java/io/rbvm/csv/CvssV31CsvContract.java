package io.rbvm.csv;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Dedicated CVE-scoped contract for CVSS v3.1 Base evidence. */
public final class CvssV31CsvContract {
    public static final String ID = "CVSS_V31_CSV_V1";
    public static final String SEMANTICS = "CVE_SCOPED_CVSS_V31_BASE_EVIDENCE";

    public static final List<String> HEADERS = List.of(
            "CVE_ID",
            "CVSS_Version",
            "CVSS_Base_Score",
            "CVSS_Vector",
            "CVSS_Source",
            "CVSS_Observed_At"
    );

    public static final Set<String> ROW_REQUIRED = Set.copyOf(HEADERS);

    private CvssV31CsvContract() {
    }

    public static HeaderMapping mapHeaders(List<String> sourceHeaders) {
        Map<String, Integer> indexes = new LinkedHashMap<>();
        Set<String> duplicates = new LinkedHashSet<>();
        List<String> normalized = new ArrayList<>(sourceHeaders.size());

        for (int index = 0; index < sourceHeaders.size(); index++) {
            String header = normalizeHeader(sourceHeaders.get(index), index == 0);
            normalized.add(header);
            if (indexes.putIfAbsent(header, index) != null) {
                duplicates.add(header);
            }
        }

        List<String> missing = HEADERS.stream()
                .filter(header -> !indexes.containsKey(header))
                .toList();
        List<String> additional = normalized.stream()
                .filter(header -> !HEADERS.contains(header))
                .toList();

        if (!duplicates.isEmpty()) {
            throw new CsvContractException("Duplicate CVSS CSV headers: " + duplicates);
        }
        if (!missing.isEmpty()) {
            throw new CsvContractException("Missing CVSS_V31_CSV_V1 headers: " + missing);
        }

        return new HeaderMapping(
                List.copyOf(normalized),
                Map.copyOf(indexes),
                List.copyOf(additional)
        );
    }

    public static CvssV31CsvEvidence parseEvidence(
            HeaderMapping mapping,
            List<String> row,
            long sourceRowNumber
    ) {
        if (row.size() != mapping.headers().size()) {
            throw new IllegalArgumentException(
                    "Expected " + mapping.headers().size() + " columns but found " + row.size());
        }

        List<String> missingValues = ROW_REQUIRED.stream()
                .filter(header -> mapping.value(row, header).trim().isEmpty())
                .sorted()
                .toList();
        if (!missingValues.isEmpty()) {
            throw new IllegalArgumentException("Missing values: " + missingValues);
        }

        BigDecimal baseScore;
        try {
            baseScore = new BigDecimal(mapping.value(row, "CVSS_Base_Score").trim());
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("CVSS_Base_Score must be numeric", exception);
        }

        Instant observedAt;
        try {
            observedAt = Instant.parse(mapping.value(row, "CVSS_Observed_At").trim());
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException(
                    "CVSS_Observed_At must be ISO-8601 with timezone", exception);
        }

        CvssV31BaseEvidence evidence = new CvssV31BaseEvidence(
                mapping.value(row, "CVE_ID"),
                mapping.value(row, "CVSS_Version"),
                baseScore,
                mapping.value(row, "CVSS_Vector"),
                mapping.value(row, "CVSS_Source"),
                observedAt
        );
        return new CvssV31CsvEvidence(sourceRowNumber, evidence);
    }

    private static String normalizeHeader(String value, boolean first) {
        String normalized = value == null ? "" : value.trim();
        if (first && normalized.startsWith("\uFEFF")) {
            normalized = normalized.substring(1);
        }
        return normalized;
    }

    public record HeaderMapping(
            List<String> headers,
            Map<String, Integer> indexes,
            List<String> additionalHeaders
    ) {
        public String value(List<String> row, String header) {
            Integer index = indexes.get(header);
            return index == null || index >= row.size() ? "" : row.get(index);
        }
    }
}
