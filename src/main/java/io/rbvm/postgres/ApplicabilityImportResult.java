package io.rbvm.postgres;

import io.rbvm.csv.ApplicabilityCsvAnalysisReport;
import io.rbvm.csv.ValidationIssue;

import java.util.List;
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
}
