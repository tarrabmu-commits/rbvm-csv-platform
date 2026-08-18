package io.rbvm.csv;

import java.util.List;
import java.util.Map;

public record ApplicabilityCsvAnalysisReport(
        String contractId,
        String semantics,
        List<String> headers,
        List<String> additionalHeaders,
        long logicalRows,
        long acceptedRows,
        long deduplicatedRows,
        long quarantinedRows,
        Map<String, Long> statusDistribution,
        List<ValidationIssue> issueSamples,
        List<Map<String, Object>> preview
) {
    public ApplicabilityCsvAnalysisReport {
        if (logicalRows < 0 || acceptedRows < 0 || deduplicatedRows < 0 || quarantinedRows < 0) {
            throw new IllegalArgumentException("Applicability CSV row counts must be non-negative");
        }
        if (logicalRows != acceptedRows + deduplicatedRows + quarantinedRows) {
            throw new IllegalArgumentException(
                    "logicalRows must equal accepted + deduplicated + quarantined rows");
        }
        headers = List.copyOf(headers);
        additionalHeaders = List.copyOf(additionalHeaders);
        statusDistribution = Map.copyOf(statusDistribution);
        issueSamples = List.copyOf(issueSamples);
        preview = List.copyOf(preview);
    }
}
