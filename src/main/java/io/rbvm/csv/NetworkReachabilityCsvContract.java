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

/** Dedicated CSV contract for scoped network reachability evidence. */
public final class NetworkReachabilityCsvContract {
    public static final String ID = "NETWORK_REACHABILITY_CSV_V1";
    public static final String SEMANTICS =
            "ASSET_ENDPOINT_ORIGIN_SCOPED_NETWORK_REACHABILITY_EVIDENCE";

    public static final List<String> HEADERS = List.of(
            "Source_Profile_Key",
            "Asset_Identity_Basis",
            "Asset_Name",
            "Asset_Source_ID",
            "Origin_Scope",
            "Origin_Label",
            "Transport_Protocol",
            "Target_Port",
            "Target_Service",
            "Reachability_Status",
            "Reachability_Method",
            "Evidence_Source",
            "Evidence_Observed_At",
            "Evidence_Source_SHA256"
    );
    public static final Set<String> ROW_REQUIRED = Set.of(
            "Source_Profile_Key",
            "Asset_Identity_Basis",
            "Asset_Name",
            "Origin_Scope",
            "Origin_Label",
            "Transport_Protocol",
            "Target_Service",
            "Reachability_Status",
            "Reachability_Method",
            "Evidence_Source",
            "Evidence_Observed_At",
            "Evidence_Source_SHA256"
    );

    private NetworkReachabilityCsvContract() {
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
            throw new CsvContractException("Duplicate network reachability CSV headers: " + duplicates);
        }
        if (!missing.isEmpty()) {
            throw new CsvContractException("Missing NETWORK_REACHABILITY_CSV_V1 headers: " + missing);
        }
        return new HeaderMapping(List.copyOf(normalized), Map.copyOf(indexes), List.copyOf(additional));
    }

    public static NetworkReachabilityCsvEvidence parseEvidence(
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

        NetworkReachabilityCsvEvidence.AssetIdentityBasis identityBasis = parseEnum(
                mapping.value(row, "Asset_Identity_Basis"),
                NetworkReachabilityCsvEvidence.AssetIdentityBasis.class,
                "Asset_Identity_Basis",
                "SOURCE_NAME_ONLY or SOURCE_STABLE_ID"
        );
        NetworkReachabilityCsvEvidence.OriginScope originScope = parseEnum(
                mapping.value(row, "Origin_Scope"),
                NetworkReachabilityCsvEvidence.OriginScope.class,
                "Origin_Scope",
                "INTERNET, EXTERNAL_PARTNER, INTERNAL_ENTERPRISE, LOCAL_SEGMENT, OTHER, or UNKNOWN"
        );
        NetworkReachabilityCsvEvidence.TransportProtocol protocol = parseEnum(
                mapping.value(row, "Transport_Protocol"),
                NetworkReachabilityCsvEvidence.TransportProtocol.class,
                "Transport_Protocol",
                "TCP, UDP, ICMP, OTHER, or UNKNOWN"
        );
        NetworkReachabilityCsvEvidence.ReachabilityStatus status = parseEnum(
                mapping.value(row, "Reachability_Status"),
                NetworkReachabilityCsvEvidence.ReachabilityStatus.class,
                "Reachability_Status",
                "REACHABLE, NOT_REACHABLE, or UNKNOWN"
        );
        NetworkReachabilityCsvEvidence.ReachabilityMethod method = parseEnum(
                mapping.value(row, "Reachability_Method"),
                NetworkReachabilityCsvEvidence.ReachabilityMethod.class,
                "Reachability_Method",
                "ACTIVE_PROBE, CONTROL_PLANE, FIREWALL_POLICY, CLOUD_CONFIGURATION, PASSIVE_OBSERVATION, OTHER, or UNKNOWN"
        );

        Integer port = null;
        String portText = mapping.value(row, "Target_Port").trim();
        if (!portText.isEmpty()) {
            try {
                port = Integer.valueOf(portText);
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException(
                        "Target_Port must be an integer between 1 and 65535 when present",
                        exception
                );
            }
        }

        Instant observedAt;
        try {
            observedAt = Instant.parse(mapping.value(row, "Evidence_Observed_At").trim());
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException(
                    "Evidence_Observed_At must be ISO-8601 with timezone", exception);
        }

        return new NetworkReachabilityCsvEvidence(
                sourceRowNumber,
                mapping.value(row, "Source_Profile_Key"),
                identityBasis,
                mapping.value(row, "Asset_Name"),
                mapping.value(row, "Asset_Source_ID"),
                originScope,
                mapping.value(row, "Origin_Label"),
                protocol,
                port,
                mapping.value(row, "Target_Service"),
                status,
                method,
                mapping.value(row, "Evidence_Source"),
                observedAt,
                mapping.value(row, "Evidence_Source_SHA256").trim()
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
