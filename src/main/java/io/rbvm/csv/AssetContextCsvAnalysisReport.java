package io.rbvm.csv;

import java.util.List;
import java.util.Map;

public record AssetContextCsvAnalysisReport(
        String contractId,
        String semantics,
        List<String> headers,
        List<String> additionalHeaders,
        long logicalRows,
        long acceptedRows,
        long deduplicatedRows,
        long quarantinedRows,
        Map<String, Long> environmentDistribution,
        Map<String, Long> criticalityDistribution,
        List<ValidationIssue> issueSamples,
        List<Map<String, Object>> preview
) {
    public AssetContextCsvAnalysisReport {
        if (logicalRows < 0 || acceptedRows < 0 || deduplicatedRows < 0 || quarantinedRows < 0) {
            throw new IllegalArgumentException("Asset context CSV row counts must be non-negative");
        }
        if (logicalRows != acceptedRows + deduplicatedRows + quarantinedRows) {
            throw new IllegalArgumentException(
                    "logicalRows must equal accepted + deduplicated + quarantined rows");
        }
        headers = List.copyOf(headers);
        additionalHeaders = List.copyOf(additionalHeaders);
        environmentDistribution = Map.copyOf(environmentDistribution);
        criticalityDistribution = Map.copyOf(criticalityDistribution);
        issueSamples = List.copyOf(issueSamples);
        preview = List.copyOf(preview);
    }
}
