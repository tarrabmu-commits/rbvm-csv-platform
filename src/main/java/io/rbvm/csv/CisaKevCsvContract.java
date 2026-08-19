package io.rbvm.csv;

import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Dedicated CVE-scoped exchange contract for snapshot-bound CISA KEV evidence. */
public final class CisaKevCsvContract {
    public static final String ID = "CISA_KEV_CSV_V1";
    public static final String SEMANTICS = "CVE_SCOPED_CISA_KEV_SNAPSHOT_MEMBERSHIP_EVIDENCE";

    public static final List<String> HEADERS = List.of(
            "CVE_ID",
            "KEV_Status",
            "KEV_Catalog_Version",
            "KEV_Catalog_SHA256",
            "KEV_Catalog_Count",
            "KEV_Source",
            "KEV_Observed_At",
            "KEV_Date_Added",
            "KEV_Due_Date",
            "Known_Ransomware_Campaign_Use"
    );

    private static final Set<String> SNAPSHOT_REQUIRED = Set.of(
            "CVE_ID",
            "KEV_Status",
            "KEV_Catalog_Version",
            "KEV_Catalog_SHA256",
            "KEV_Catalog_Count",
            "KEV_Source",
            "KEV_Observed_At"
    );

    private CisaKevCsvContract() {
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
            throw new CsvContractException("Duplicate KEV CSV headers: " + duplicates);
        }
        if (!missing.isEmpty()) {
            throw new CsvContractException("Missing CISA_KEV_CSV_V1 headers: " + missing);
        }

        return new HeaderMapping(
                List.copyOf(normalized),
                Map.copyOf(indexes),
                List.copyOf(additional)
        );
    }

    public static CisaKevCsvEvidence parseEvidence(
            HeaderMapping mapping,
            List<String> row,
            long sourceRowNumber
    ) {
        if (row.size() != mapping.headers().size()) {
            throw new IllegalArgumentException(
                    "Expected " + mapping.headers().size() + " columns but found " + row.size());
        }

        List<String> missingValues = SNAPSHOT_REQUIRED.stream()
                .filter(header -> mapping.value(row, header).trim().isEmpty())
                .sorted()
                .toList();
        if (!missingValues.isEmpty()) {
            throw new IllegalArgumentException("Missing values: " + missingValues);
        }

        CisaKevEvidence.Status status;
        try {
            status = CisaKevEvidence.Status.valueOf(
                    mapping.value(row, "KEV_Status").trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("KEV_Status must be LISTED or NOT_LISTED", exception);
        }
        if (status == CisaKevEvidence.Status.UNKNOWN) {
            throw new IllegalArgumentException(
                    "KEV_Status UNKNOWN is represented by absence of usable snapshot evidence, not by a CISA_KEV_CSV_V1 row"
            );
        }

        int catalogCount;
        try {
            catalogCount = Integer.parseInt(mapping.value(row, "KEV_Catalog_Count").trim());
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("KEV_Catalog_Count must be a positive integer", exception);
        }

        Instant observedAt;
        try {
            observedAt = Instant.parse(mapping.value(row, "KEV_Observed_At").trim());
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException(
                    "KEV_Observed_At must be ISO-8601 with timezone", exception);
        }

        CisaKevCatalogSnapshot snapshot = new CisaKevCatalogSnapshot(
                mapping.value(row, "KEV_Catalog_Version"),
                mapping.value(row, "KEV_Source"),
                observedAt,
                mapping.value(row, "KEV_Catalog_SHA256"),
                catalogCount,
                catalogCount
        );

        CisaKevEvidence evidence;
        if (status == CisaKevEvidence.Status.LISTED) {
            String dateAddedValue = requiredListingValue(mapping, row, "KEV_Date_Added");
            String dueDateValue = requiredListingValue(mapping, row, "KEV_Due_Date");
            String ransomwareValue = requiredListingValue(
                    mapping, row, "Known_Ransomware_Campaign_Use");
            LocalDate dateAdded = parseDate(dateAddedValue, "KEV_Date_Added");
            LocalDate dueDate = parseDate(dueDateValue, "KEV_Due_Date");
            CisaKevEvidence.RansomwareCampaignUse ransomwareCampaignUse;
            try {
                ransomwareCampaignUse = CisaKevEvidence.RansomwareCampaignUse.valueOf(
                        ransomwareValue.toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException exception) {
                throw new IllegalArgumentException(
                        "Known_Ransomware_Campaign_Use must be KNOWN or UNKNOWN", exception);
            }
            evidence = CisaKevEvidence.listed(
                    mapping.value(row, "CVE_ID"),
                    snapshot,
                    dateAdded,
                    dueDate,
                    ransomwareCampaignUse
            );
        } else {
            requireBlank(mapping, row, "KEV_Date_Added");
            requireBlank(mapping, row, "KEV_Due_Date");
            requireBlank(mapping, row, "Known_Ransomware_Campaign_Use");
            evidence = CisaKevEvidence.notListed(mapping.value(row, "CVE_ID"), snapshot);
        }

        return new CisaKevCsvEvidence(sourceRowNumber, evidence);
    }

    private static String requiredListingValue(
            HeaderMapping mapping,
            List<String> row,
            String header
    ) {
        String value = mapping.value(row, header).trim();
        if (value.isEmpty()) {
            throw new IllegalArgumentException(header + " is required when KEV_Status=LISTED");
        }
        return value;
    }

    private static void requireBlank(HeaderMapping mapping, List<String> row, String header) {
        if (!mapping.value(row, header).trim().isEmpty()) {
            throw new IllegalArgumentException(
                    header + " must be blank when KEV_Status=NOT_LISTED");
        }
    }

    private static LocalDate parseDate(String value, String field) {
        try {
            return LocalDate.parse(value);
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException(field + " must be an ISO-8601 date", exception);
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
