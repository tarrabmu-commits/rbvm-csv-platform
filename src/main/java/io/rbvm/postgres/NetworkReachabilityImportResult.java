package io.rbvm.postgres;

import io.rbvm.csv.NetworkReachabilityCsvAnalysisReport;
import io.rbvm.csv.ValidationIssue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Transactional persistence outcome for one NETWORK_REACHABILITY_CSV_V1 file. */
public record NetworkReachabilityImportResult(
        NetworkReachabilityCsvAnalysisReport analysis,
        long insertedSnapshots,
        long replayedSnapshots,
        long snapshotConflictGroups,
        long insertedEvidence,
        long replayedEvidence,
        long persistenceQuarantinedRows,
        List<ValidationIssue> persistenceIssues
) {
    public NetworkReachabilityImportResult {
        Objects.requireNonNull(analysis, "analysis");
        if (insertedSnapshots < 0 || replayedSnapshots < 0 || snapshotConflictGroups < 0
                || insertedEvidence < 0 || replayedEvidence < 0
                || persistenceQuarantinedRows < 0) {
            throw new IllegalArgumentException("Network reachability import counts must be non-negative");
        }
        if (analysis.acceptedRows()
                != insertedEvidence + replayedEvidence + persistenceQuarantinedRows) {
            throw new IllegalArgumentException(
                    "acceptedRows must equal inserted + replayed + persistence-quarantined rows");
        }
        persistenceIssues = List.copyOf(persistenceIssues);
    }

    public long totalQuarantinedRows() {
        return analysis.quarantinedRows() + persistenceQuarantinedRows;
    }

    public long totalDeduplicatedRows() {
        return analysis.deduplicatedRows() + replayedEvidence;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("contractId", analysis.contractId());
        output.put("semantics", analysis.semantics());
        output.put("logicalRows", analysis.logicalRows());
        output.put("acceptedRows", analysis.acceptedRows());
        output.put("insertedSnapshots", insertedSnapshots);
        output.put("replayedSnapshots", replayedSnapshots);
        output.put("snapshotConflictGroups", snapshotConflictGroups);
        output.put("insertedEvidence", insertedEvidence);
        output.put("replayedEvidence", replayedEvidence);
        output.put("contractDeduplicatedRows", analysis.deduplicatedRows());
        output.put("persistenceQuarantinedRows", persistenceQuarantinedRows);
        output.put("contractQuarantinedRows", analysis.quarantinedRows());
        output.put("totalDeduplicatedRows", totalDeduplicatedRows());
        output.put("totalQuarantinedRows", totalQuarantinedRows());
        output.put("originScopeDistribution", analysis.originScopeDistribution());
        output.put("protocolDistribution", analysis.protocolDistribution());
        output.put("reachabilityStatusDistribution", analysis.reachabilityStatusDistribution());
        output.put("reachabilityMethodDistribution", analysis.reachabilityMethodDistribution());
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
