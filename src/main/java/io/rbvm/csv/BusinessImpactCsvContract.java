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

/** Dedicated CSV contract for source-reported qualitative Business/Mission Impact evidence. */
public final class BusinessImpactCsvContract {
    public static final String ID = "BUSINESS_IMPACT_CSV_V1";
    public static final String SEMANTICS =
            "ASSET_SERVICE_SCOPED_BUSINESS_MISSION_IMPACT_EVIDENCE";

    public static final List<String> HEADERS = List.of(
            "Source_Profile_Key",
            "Asset_Identity_Basis",
            "Asset_Name",
            "Asset_Source_ID",
            "Business_Service",
            "Impact_Dimension",
            "Impact_Level",
            "Impact_Method",
            "Impact_Statement",
            "Impact_Source",
            "Impact_Observed_At",
            "Impact_Source_SHA256"
    );

    public static final Set<String> ROW_REQUIRED = Set.of(
            "Source_Profile_Key",
            "Asset_Identity_Basis",
            "Asset_Name",
            "Business_Service",
            "Impact_Dimension",
            "Impact_Level",
            "Impact_Method",
            "Impact_Statement",
            "Impact_Source",
            "Impact_Observed_At",
            "Impact_Source_SHA256"
    );

    private BusinessImpactCsvContract() {
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
        List<String> missing = HEADERS.stream()
                .filter(header -> !indexes.containsKey(header))
                .toList();
        List<String> additional = normalized.stream()
                .filter(header -> !HEADERS.contains(header))
                .toList();
        if (!duplicates.isEmpty()) {
            throw new CsvContractException("Duplicate Business Impact CSV headers: " + duplicates);
        }
        if (!missing.isEmpty()) {
            throw new CsvContractException("Missing BUSINESS_IMPACT_CSV_V1 headers: " + missing);
        }
        return new HeaderMapping(List.copyOf(normalized), Map.copyOf(indexes), List.copyOf(additional));
    }

    public static BusinessImpactCsvEvidence parseEvidence(
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

        BusinessImpactCsvEvidence.AssetIdentityBasis identityBasis = parseEnum(
                mapping.value(row, "Asset_Identity_Basis"),
                BusinessImpactCsvEvidence.AssetIdentityBasis.class,
                "Asset_Identity_Basis",
                "SOURCE_NAME_ONLY or SOURCE_STABLE_ID"
        );
        BusinessImpactCsvEvidence.ImpactDimension dimension = parseEnum(
                mapping.value(row, "Impact_Dimension"),
                BusinessImpactCsvEvidence.ImpactDimension.class,
                "Impact_Dimension",
                "AVAILABILITY, INTEGRITY, CONFIDENTIALITY, SAFETY, FINANCIAL, REGULATORY, OPERATIONAL, REPUTATIONAL, MISSION, OTHER, or UNKNOWN"
        );
        BusinessImpactCsvEvidence.ImpactLevel level = parseEnum(
                mapping.value(row, "Impact_Level"),
                BusinessImpactCsvEvidence.ImpactLevel.class,
                "Impact_Level",
                "SEVERE, HIGH, MODERATE, LOW, NEGLIGIBLE, or UNKNOWN"
        );
        BusinessImpactCsvEvidence.ImpactMethod method = parseEnum(
                mapping.value(row, "Impact_Method"),
                BusinessImpactCsvEvidence.ImpactMethod.class,
                "Impact_Method",
                "BUSINESS_IMPACT_ANALYSIS, SERVICE_OWNER_ATTESTATION, POLICY_CLASSIFICATION, INCIDENT_ANALYSIS, OTHER, or UNKNOWN"
        );

        Instant observedAt;
        try {
            observedAt = Instant.parse(mapping.value(row, "Impact_Observed_At").trim());
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException(
                    "Impact_Observed_At must be ISO-8601 with timezone", exception);
        }

        return new BusinessImpactCsvEvidence(
                sourceRowNumber,
                mapping.value(row, "Source_Profile_Key"),
                identityBasis,
                mapping.value(row, "Asset_Name"),
                mapping.value(row, "Asset_Source_ID"),
                mapping.value(row, "Business_Service"),
                dimension,
                level,
                method,
                mapping.value(row, "Impact_Statement"),
                mapping.value(row, "Impact_Source"),
                observedAt,
                mapping.value(row, "Impact_Source_SHA256").trim()
        );
    }

    private static <E extends Enum<E>> E parseEnum(
            String value,
            Class<E> type,
            String field,
            String allowed
    ) {
        try {
            return Enum.valueOf(type, value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(field + " must be " + allowed, exception);
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
