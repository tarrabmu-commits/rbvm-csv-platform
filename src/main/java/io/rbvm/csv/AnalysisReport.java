package io.rbvm.csv;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record AnalysisReport(
        String contractId,
        String semantics,
        long fileSizeBytes,
        String fileSha256,
        List<String> headers,
        List<String> additionalHeaders,
        long logicalRows,
        long acceptedRows,
        long deduplicatedRows,
        long quarantinedRows,
        long activeRows,
        long resolvedRows,
        long uniqueAgents,
        long uniqueCves,
        long uniqueProducts,
        long uniqueExposureKeys,
        long repeatedExposureGroups,
        long repeatedExposureObservations,
        long exposureGroupsWithSeverityChanges,
        long uniqueCaseKeys,
        long casesWithMultipleProducts,
        int maximumProductsPerCase,
        Map<String, Long> severityDistribution,
        Instant minimumDetectedAt,
        Instant maximumDetectedAt,
        Map<String, Integer> maximumFieldLengths,
        long valuesWithEmbeddedNewlines,
        long rowsWithoutHttpReferences,
        List<ValidationIssue> issueSamples,
        List<Map<String, Object>> preview
) {
    public Map<String, Object> toMap() {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("contractId", contractId);
        root.put("semantics", semantics);

        Map<String, Object> file = new LinkedHashMap<>();
        file.put("sizeBytes", fileSizeBytes);
        file.put("sha256", fileSha256);
        root.put("file", file);

        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("headers", headers);
        schema.put("additionalHeaders", additionalHeaders);
        root.put("schema", schema);

        Map<String, Object> ledger = new LinkedHashMap<>();
        ledger.put("logicalRows", logicalRows);
        ledger.put("acceptedRows", acceptedRows);
        ledger.put("deduplicatedRows", deduplicatedRows);
        ledger.put("quarantinedRows", quarantinedRows);
        ledger.put("activeRows", activeRows);
        ledger.put("resolvedRows", resolvedRows);
        root.put("ledger", ledger);

        Map<String, Object> identity = new LinkedHashMap<>();
        identity.put("uniqueAgents", uniqueAgents);
        identity.put("uniqueCves", uniqueCves);
        identity.put("uniqueProducts", uniqueProducts);
        identity.put("uniqueExposureKeys", uniqueExposureKeys);
        identity.put("repeatedExposureGroups", repeatedExposureGroups);
        identity.put("repeatedExposureObservations", repeatedExposureObservations);
        identity.put("exposureGroupsWithSeverityChanges", exposureGroupsWithSeverityChanges);
        identity.put("uniqueCaseKeys", uniqueCaseKeys);
        identity.put("casesWithMultipleProducts", casesWithMultipleProducts);
        identity.put("maximumProductsPerCase", maximumProductsPerCase);
        root.put("identity", identity);

        root.put("severityDistribution", severityDistribution);

        Map<String, Object> time = new LinkedHashMap<>();
        time.put("minimumDetectedAt", minimumDetectedAt == null ? null : minimumDetectedAt.toString());
        time.put("maximumDetectedAt", maximumDetectedAt == null ? null : maximumDetectedAt.toString());
        root.put("time", time);

        Map<String, Object> quality = new LinkedHashMap<>();
        quality.put("maximumFieldLengths", maximumFieldLengths);
        quality.put("valuesWithEmbeddedNewlines", valuesWithEmbeddedNewlines);
        quality.put("rowsWithoutHttpReferences", rowsWithoutHttpReferences);
        quality.put("issueSamples", issueSamples.stream().map(issue -> Map.of(
                "rowNumber", issue.rowNumber(),
                "level", issue.level().name(),
                "code", issue.code(),
                "message", issue.message()
        )).toList());
        root.put("quality", quality);
        root.put("preview", preview);
        return root;
    }
}
