package io.rbvm.csv;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Opt-in evidence contract with stable identities and explicit finding lifecycle. */
public final class CsvContractV2 {
    public static final String ID = "WAZUH_CSV_V2";
    public static final String SEMANTICS = "EXPLICIT_FINDING_LIFECYCLE_EXPORT";

    public static final List<String> HEADERS = List.of(
            "Agent", "Agent_ID", "CVE_ID", "Severity", "CVE_Description",
            "Affected_Product", "Package_Version", "Package_Architecture",
            "References", "OS_name", "Finding_Status", "Detected_At", "Resolved_At"
    );

    public static final Set<String> ROW_REQUIRED = Set.of(
            "Agent", "Agent_ID", "CVE_ID", "Affected_Product", "Package_Version",
            "Package_Architecture", "Finding_Status", "Detected_At"
    );

    public static final List<String> INTELLIGENCE_HEADERS = List.of(
            "CVSS_Version", "CVSS_Base_Score", "CVSS_Vector",
            "EPSS_Probability", "EPSS_Percentile", "Known_Exploited",
            "KEV_Date_Added", "KEV_Due_Date", "Intel_Observed_At",
            "Intel_Source_References"
    );

    private CsvContractV2() {
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
        List<String> missing = HEADERS.stream().filter(h -> !indexes.containsKey(h)).toList();
        List<String> additional = normalized.stream().filter(h -> !HEADERS.contains(h)).toList();
        if (!duplicates.isEmpty()) {
            throw new CsvContractException("Duplicate CSV headers: " + duplicates);
        }
        if (!missing.isEmpty()) {
            throw new CsvContractException("Missing WAZUH_CSV_V2 headers: " + missing);
        }
        return new HeaderMapping(List.copyOf(normalized), Map.copyOf(indexes), List.copyOf(additional));
    }

    public static boolean supported(String contractId) {
        return CsvContractV1.ID.equals(contractId) || ID.equals(contractId);
    }

    public static String requireSupported(String contractId) {
        String value = contractId == null || contractId.isBlank() ? CsvContractV1.ID : contractId.trim();
        if (!supported(value)) {
            throw new CsvContractException("Unsupported CSV contract: " + value
                    + "; supported contracts are WAZUH_CSV_V1 and WAZUH_CSV_V2");
        }
        return value;
    }

    private static String normalizeHeader(String value, boolean first) {
        String normalized = value == null ? "" : value.trim();
        return first && normalized.startsWith("\uFEFF") ? normalized.substring(1) : normalized;
    }

    public record HeaderMapping(List<String> headers, Map<String, Integer> indexes,
                                List<String> additionalHeaders) {
        public String value(List<String> row, String header) {
            Integer index = indexes.get(header);
            return index == null || index >= row.size() ? "" : row.get(index);
        }
    }
}
