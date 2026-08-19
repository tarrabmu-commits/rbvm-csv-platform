package io.rbvm.csv;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Validation/preview ledger for one CISA_KEV_CSV_V1 file. */
public record CisaKevCsvAnalysisReport(
        String contractId,
        String semantics,
        List<String> headers,
        List<String> additionalHeaders,
        long logicalRows,
        long acceptedRows,
        long deduplicatedRows,
        long quarantinedRows,
        long listedRows,
        long notListedRows,
        long uniqueCves,
        long uniqueSnapshots,
        List<ValidationIssue> issueSamples,
        List<Map<String, Object>> preview
) {
    public CisaKevCsvAnalysisReport {
        if (logicalRows < 0 || acceptedRows < 0 || deduplicatedRows < 0
                || quarantinedRows < 0 || listedRows < 0 || notListedRows < 0
                || uniqueCves < 0 || uniqueSnapshots < 0) {
            throw new IllegalArgumentException("KEV CSV counts must be non-negative");
        }
        if (logicalRows != acceptedRows + deduplicatedRows + quarantinedRows) {
            throw new IllegalArgumentException(
                    "logicalRows must equal accepted + deduplicated + quarantined rows");
        }
        if (acceptedRows != listedRows + notListedRows) {
            throw new IllegalArgumentException(
                    "acceptedRows must equal LISTED + NOT_LISTED rows");
        }
        headers = List.copyOf(headers);
        additionalHeaders = List.copyOf(additionalHeaders);
        issueSamples = List.copyOf(issueSamples);
        preview = List.copyOf(preview);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("contractId", contractId);
        output.put("semantics", semantics);
        output.put("headers", headers);
        output.put("additionalHeaders", additionalHeaders);
        output.put("logicalRows", logicalRows);
        output.put("acceptedRows", acceptedRows);
        output.put("deduplicatedRows", deduplicatedRows);
        output.put("quarantinedRows", quarantinedRows);
        output.put("listedRows", listedRows);
        output.put("notListedRows", notListedRows);
        output.put("uniqueCves", uniqueCves);
        output.put("uniqueSnapshots", uniqueSnapshots);
        output.put("issueSamples", issueSamples.stream().map(issue -> Map.of(
                "rowNumber", issue.rowNumber(),
                "level", issue.level().name(),
                "code", issue.code(),
                "message", issue.message()
        )).toList());
        output.put("preview", preview);
        return output;
    }
}
