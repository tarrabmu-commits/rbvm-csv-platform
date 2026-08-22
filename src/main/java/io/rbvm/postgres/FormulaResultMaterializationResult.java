package io.rbvm.postgres;

import io.rbvm.decision.RbvmFormulaV1Explanation;

import java.util.Objects;

/** Replay-verified outcome of exact Decision Input V3 to Formula V1 materialization. */
public record FormulaResultMaterializationResult(
        RbvmFormulaV1Explanation explanation,
        FormulaResultInstallResult installResult,
        StoredFormulaResult storedResult
) {
    public FormulaResultMaterializationResult {
        explanation = Objects.requireNonNull(explanation, "explanation");
        installResult = Objects.requireNonNull(installResult, "installResult");
        storedResult = Objects.requireNonNull(storedResult, "storedResult");
        if (!installResult.installedOrReplayed()) {
            throw new IllegalArgumentException(
                    "Formula materialization result requires an inserted or replayed install"
            );
        }
        if (!explanation.canonicalSha256().equals(installResult.requestedExplanationSha256())
                || !explanation.canonicalSha256().equals(storedResult.explanationSha256())
                || !explanation.inputSnapshotSha256().equals(storedResult.inputSnapshotSha256())) {
            throw new IllegalArgumentException(
                    "Formula materialization identities must match the exact explanation and snapshot"
            );
        }
    }

    public boolean replayed() {
        return installResult.status() == FormulaResultInstallResult.Status.REPLAYED;
    }
}
