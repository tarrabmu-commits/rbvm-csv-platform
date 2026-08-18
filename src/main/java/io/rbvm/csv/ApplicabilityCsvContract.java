package io.rbvm.csv;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Dedicated CSV contract for finding-scoped applicability assessments.
 *
 * <p>Row presence means an explicit assessment exists. Absence means the finding remains unassessed
 * and therefore UNKNOWN. An explicit UNKNOWN row means the finding was assessed but the available
 * evidence was inconclusive.</p>
 */
public final class ApplicabilityCsvContract {
    public static final String ID = "APPLICABILITY_CSV_V1";
    public static final String SEMANTICS = "FINDING_SCOPED_EXPLICIT_ASSESSMENT";

    public static final List<String> HEADERS = List.of(
            "Finding_ID",
            "Applicability_Status",
            "Applicability_Reason",
            "Evidence_Source",
            "Evaluated_At"
    );

    public static final Set<String> ROW_REQUIRED = Set.copyOf(HEADERS);

    private ApplicabilityCsvContract() {
    }

    public static HeaderMapping mapHeaders(List<String> sourceHeaders) {
        Map<String, Integer> indexes = new LinkedHashMap<>();
        Set<String> duplicates = new LinkedHashSet<>();
        List<String> normalized = new ArrayList<>(sourceHeaders.size());

        for (int i = 0; i < sourceHeaders.size(); i++) {
            String header = normalizeHeader(sourceHeaders.get(i), i == 0);
            normalized.add(header);
            if (indexes.putIfAbsent(header, i) != null) {
                duplicates.add(header);
            }
        }

        List<String> missing = HEADERS.stream().filter(header -> !indexes.containsKey(header)).toList();
        List<String> additional = normalized.stream().filter(header -> !HEADERS.contains(header)).toList();

        if (!duplicates.isEmpty()) {
            throw new CsvContractException("Duplicate applicability CSV headers: " + duplicates);
        }
        if (!missing.isEmpty()) {
            throw new CsvContractException("Missing APPLICABILITY_CSV_V1 headers: " + missing);
        }

        return new HeaderMapping(List.copyOf(normalized), Map.copyOf(indexes), List.copyOf(additional));
    }

    public static ApplicabilityCsvAssessment parseAssessment(
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

        UUID findingId;
        try {
            findingId = UUID.fromString(mapping.value(row, "Finding_ID").trim());
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Finding_ID must be a UUID", exception);
        }

        ApplicabilityEvidence.Status status;
        try {
            status = ApplicabilityEvidence.Status.valueOf(
                    mapping.value(row, "Applicability_Status").trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                    "Applicability_Status must be APPLICABLE, NOT_APPLICABLE, or UNKNOWN", exception);
        }

        Instant evaluatedAt;
        try {
            evaluatedAt = Instant.parse(mapping.value(row, "Evaluated_At").trim());
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException(
                    "Evaluated_At must be ISO-8601 with timezone", exception);
        }

        return new ApplicabilityCsvAssessment(
                sourceRowNumber,
                findingId,
                status,
                mapping.value(row, "Applicability_Reason"),
                mapping.value(row, "Evidence_Source"),
                evaluatedAt
        );
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
