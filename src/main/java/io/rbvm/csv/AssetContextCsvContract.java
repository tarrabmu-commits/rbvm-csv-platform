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

/** Dedicated CSV contract for explicit asset-scoped organizational context evidence. */
public final class AssetContextCsvContract {
    public static final String ID = "ASSET_CONTEXT_CSV_V1";
    public static final String SEMANTICS = "ASSET_SCOPED_ORGANIZATIONAL_CONTEXT_EVIDENCE";

    public static final List<String> HEADERS = List.of(
            "Source_Profile_Key",
            "Asset_Name",
            "Environment",
            "Business_Service",
            "Business_Owner",
            "Business_Criticality",
            "Context_Source",
            "Context_Observed_At",
            "Context_Source_SHA256"
    );
    public static final Set<String> ROW_REQUIRED = Set.copyOf(HEADERS);

    private AssetContextCsvContract() {
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
            throw new CsvContractException("Duplicate asset context CSV headers: " + duplicates);
        }
        if (!missing.isEmpty()) {
            throw new CsvContractException("Missing ASSET_CONTEXT_CSV_V1 headers: " + missing);
        }
        return new HeaderMapping(List.copyOf(normalized), Map.copyOf(indexes), List.copyOf(additional));
    }

    public static AssetContextCsvEvidence parseEvidence(
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

        AssetContextCsvEvidence.Environment environment;
        try {
            environment = AssetContextCsvEvidence.Environment.valueOf(
                    mapping.value(row, "Environment").trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                    "Environment must be PRODUCTION, PRE_PRODUCTION, DEVELOPMENT, TEST, SANDBOX, DISASTER_RECOVERY, or UNKNOWN",
                    exception);
        }

        AssetContextCsvEvidence.BusinessCriticality criticality;
        try {
            criticality = AssetContextCsvEvidence.BusinessCriticality.valueOf(
                    mapping.value(row, "Business_Criticality").trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                    "Business_Criticality must be MISSION_CRITICAL, HIGH, MODERATE, LOW, or UNKNOWN",
                    exception);
        }

        Instant observedAt;
        try {
            observedAt = Instant.parse(mapping.value(row, "Context_Observed_At").trim());
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException(
                    "Context_Observed_At must be ISO-8601 with timezone", exception);
        }

        return new AssetContextCsvEvidence(
                sourceRowNumber,
                mapping.value(row, "Source_Profile_Key"),
                mapping.value(row, "Asset_Name"),
                environment,
                mapping.value(row, "Business_Service"),
                mapping.value(row, "Business_Owner"),
                criticality,
                mapping.value(row, "Context_Source"),
                observedAt,
                mapping.value(row, "Context_Source_SHA256").trim()
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
