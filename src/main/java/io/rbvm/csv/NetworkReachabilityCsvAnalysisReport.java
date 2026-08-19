package io.rbvm.csv;

import java.util.List;
import java.util.Map;

public record NetworkReachabilityCsvAnalysisReport(
        String contractId,
        String semantics,
        List<String> headers,
        List<String> additionalHeaders,
        long logicalRows,
        long acceptedRows,
        long deduplicatedRows,
        long quarantinedRows,
        Map<String, Long> originScopeDistribution,
        Map<String, Long> protocolDistribution,
        Map<String, Long> reachabilityStatusDistribution,
        Map<String, Long> reachabilityMethodDistribution,
        List<ValidationIssue> issueSamples,
        List<Map<String, Object>> preview
) {
    public NetworkReachabilityCsvAnalysisReport {
        if (logicalRows < 0 || acceptedRows < 0 || deduplicatedRows < 0 || quarantinedRows < 0) {
            throw new IllegalArgumentException("Network reachability CSV row counts must be non-negative");
        }
        if (logicalRows != acceptedRows + deduplicatedRows + quarantinedRows) {
            throw new IllegalArgumentException(
                    "logicalRows must equal accepted + deduplicated + quarantined rows");
        }
        headers = List.copyOf(headers);
        additionalHeaders = List.copyOf(additionalHeaders);
        originScopeDistribution = Map.copyOf(originScopeDistribution);
        protocolDistribution = Map.copyOf(protocolDistribution);
        reachabilityStatusDistribution = Map.copyOf(reachabilityStatusDistribution);
        reachabilityMethodDistribution = Map.copyOf(reachabilityMethodDistribution);
        issueSamples = List.copyOf(issueSamples);
        preview = List.copyOf(preview);
    }
}
