package io.rbvm.csv;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Dedicated CVE-scoped exchange contract for FIRST EPSS probability evidence. */
public final class EpssCsvContract {
    public static final String ID = "EPSS_CSV_V1";
    public static final String SEMANTICS = "CVE_SCOPED_FIRST_EPSS_PROBABILITY_EVIDENCE";

    public static final List<String> HEADERS = List.of(
            "CVE_ID",
            "EPSS_Probability",
            "EPSS_Percentile",
            "EPSS_Model_Version",
            "EPSS_Score_Date",
            "EPSS_Source",
            "EPSS_Observed_At",
            "EPSS_Source_SHA256"
    );

    public static final Set<String> ROW_REQUIRED = Set.copyOf(HEADERS);

    private EpssCsvContract() {
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
            throw new CsvContractException("Duplicate EPSS CSV headers: " + duplicates);
        }
        if (!missing.isEmpty()) {
            throw new CsvContractException("Missing EPSS_CSV_V1 headers: " + missing);
        }

        return new HeaderMapping(
                List.copyOf(normalized),
                Map.copyOf(indexes),
                List.copyOf(additional)
        );
    }

    public static EpssCsvEvidence parseEvidence(
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

        BigDecimal probability = parseProbability(
                mapping.value(row, "EPSS_Probability"), "EPSS_Probability");
        BigDecimal percentile = parseProbability(
                mapping.value(row, "EPSS_Percentile"), "EPSS_Percentile");

        LocalDate scoreDate;
        try {
            scoreDate = LocalDate.parse(mapping.value(row, "EPSS_Score_Date").trim());
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException(
                    "EPSS_Score_Date must be an ISO-8601 date", exception);
        }

        Instant observedAt;
        try {
            observedAt = Instant.parse(mapping.value(row, "EPSS_Observed_At").trim());
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException(
                    "EPSS_Observed_At must be ISO-8601 with timezone", exception);
        }

        EpssEvidence evidence = new EpssEvidence(
                mapping.value(row, "CVE_ID"),
                probability,
                percentile,
                mapping.value(row, "EPSS_Model_Version"),
                scoreDate,
                mapping.value(row, "EPSS_Source"),
                observedAt,
                mapping.value(row, "EPSS_Source_SHA256")
        );
        return new EpssCsvEvidence(sourceRowNumber, evidence);
    }

    private static BigDecimal parseProbability(String value, String field) {
        try {
            return new BigDecimal(value.trim());
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(field + " must be numeric", exception);
        }
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
