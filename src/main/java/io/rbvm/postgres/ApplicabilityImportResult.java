package io.rbvm.postgres;

import io.rbvm.csv.ApplicabilityCsvAnalysisReport;
import io.rbvm.csv.ValidationIssue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Transactional persistence outcome for one APPLICABILITY_CSV_V1 file.
 *
 * <p>Contract-level quarantine/deduplication remains in {@link ApplicabilityCsvAnalysisReport}.
 * Persistence-level quarantine covers rows that are syntactically valid but cannot be attached
 * safely to the selected tenant/finding history.</p>
 */
public record ApplicabilityImportResult(
        ApplicabilityCsvAnalysisReport analysis,
        long insertedAssessments,
        long replayedAssessments,
        long persistenceQuarantinedRows,
        List<ValidationIssue> persistenceIssues
) {
    public ApplicabilityImportResult {
        Objects.requireNonNull(analysis, "analysis");
        if (insertedAssessments < 0 || replayedAssessments < 0 || persistenceQuarantinedRows < 0) {
            throw new IllegalArgumentException("Applicability import counts must be non-negative");
        }
        if (analysis.acceptedRows()
                != insertedAssessments + replayedAssessments + persistenceQuarantinedRows) {
            throw new IllegalArgumentException(
                    "acceptedRows must equal inserted + replayed + persistence-quarantined rows");
        }
        persistenceIssues = List.copyOf(persistenceIssues);
    }

    public long totalQuarantinedRows() {
        return analysis.quarantinedRows() + persistenceQuarantinedRows;
    }

    public long totalDeduplicatedRows() {
        return analysis.deduplicatedRows() + replayedAssessments;
    }

    /** Stable HTTP/JSON representation without exposing JDBC implementation details. */
    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("contractId", analysis.contractId());
        output.put("semantics", analysis.semantics());
        output.put("logicalRows", analysis.logicalRows());
        output.put("acceptedRows", analysis.acceptedRows());
        output.put("insertedAssessments", insertedAssessments);
        output.put("replayedAssessments", replayedAssessments);
        output.put("contractDeduplicatedRows", analysis.deduplicatedRows());
        output.put("persistenceQuarantinedRows", persistenceQuarantinedRows);
        output.put("contractQuarantinedRows", analysis.quarantinedRows());
        output.put("totalDeduplicatedRows", totalDeduplicatedRows());
        output.put("totalQuarantinedRows", totalQuarantinedRows());
        output.put("statusDistribution", analysis.statusDistribution());
        output.put("contractIssues", issueMaps(analysis.issueSamples()));
        output.put("persistenceIssues", issueMaps(persistenceIssues));
        return output;
    }

    private static List<Map<String, Object>> issueMaps(List<ValidationIssue> issues) {
        List<Map<String, Object>> output = new ArrayList<>(issues.size());
        for (ValidationIssue issue : issues) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("rowNumber", issue.rowNumber());
            item.put("level", issue.level().name());
            item.put("code", issue.code());
            item.put("message", issue.message());
            output.add(Map.copyOf(item));
        }
        return List.copyOf(output);
    }
}
