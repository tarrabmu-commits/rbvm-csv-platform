package io.rbvm.csv;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class CsvContractV1 {
    public static final String ID = "WAZUH_CSV_V1";

    public static final List<String> HEADERS = List.of(
            "Agent",
            "CVE_ID",
            "Severity",
            "CVE_Description",
            "Affected_Product",
            "References",
            "OS_name",
            "Detected_At"
    );

    public static final Set<String> ROW_REQUIRED = Set.of(
            "Agent",
            "CVE_ID",
            "Affected_Product",
            "Detected_At"
    );

    private CsvContractV1() {
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
            throw new CsvContractException("Missing WAZUH_CSV_V1 headers: " + missing);
        }

        return new HeaderMapping(List.copyOf(normalized), Map.copyOf(indexes), List.copyOf(additional));
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

