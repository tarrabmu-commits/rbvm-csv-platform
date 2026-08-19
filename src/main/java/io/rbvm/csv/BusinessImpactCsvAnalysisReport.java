package io.rbvm.csv;

import java.util.List;
import java.util.Map;

public record BusinessImpactCsvAnalysisReport(
        String contractId,
        String semantics,
        List<String> headers,
        List<String> additionalHeaders,
        long logicalRows,
        long acceptedRows,
        long deduplicatedRows,
        long quarantinedRows,
        Map<String, Long> impactDimensionDistribution,
        Map<String, Long> impactLevelDistribution,
        Map<String, Long> impactMethodDistribution,
        List<ValidationIssue> issueSamples,
        List<Map<String, Object>> preview
) {
    public BusinessImpactCsvAnalysisReport {
        if (logicalRows < 0 || acceptedRows < 0 || deduplicatedRows < 0 || quarantinedRows < 0) {
            throw new IllegalArgumentException("Business Impact CSV row counts must be non-negative");
        }
        if (logicalRows != acceptedRows + deduplicatedRows + quarantinedRows) {
            throw new IllegalArgumentException(
                    "logicalRows must equal accepted + deduplicated + quarantined rows");
        }
        headers = List.copyOf(headers);
        additionalHeaders = List.copyOf(additionalHeaders);
        impactDimensionDistribution = Map.copyOf(impactDimensionDistribution);
        impactLevelDistribution = Map.copyOf(impactLevelDistribution);
        impactMethodDistribution = Map.copyOf(impactMethodDistribution);
        issueSamples = List.copyOf(issueSamples);
        preview = List.copyOf(preview);
    }
}
