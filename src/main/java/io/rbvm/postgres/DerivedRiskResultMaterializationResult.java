package io.rbvm.postgres;

import io.rbvm.decision.RbvmDerivedRiskCanonicalResult;

import java.util.Objects;

/** Replay-verified outcome of exact Decision Input V3 plus exact methodology materialization. */
public record DerivedRiskResultMaterializationResult(
        RbvmDerivedRiskCanonicalResult canonicalResult,
        DerivedRiskResultInstallResult installResult,
        StoredDerivedRiskResult storedResult
) {
    public DerivedRiskResultMaterializationResult {
        canonicalResult = Objects.requireNonNull(canonicalResult, "canonicalResult");
        installResult = Objects.requireNonNull(installResult, "installResult");
        storedResult = Objects.requireNonNull(storedResult, "storedResult");
        if (!installResult.installedOrReplayed()) {
            throw new IllegalArgumentException(
                    "Derived risk materialization requires an inserted or replayed install"
            );
        }
        var evaluation = canonicalResult.evaluation();
        var definition = evaluation.definition();
        if (!canonicalResult.canonicalSha256().equals(installResult.requestedResultSha256())
                || !canonicalResult.canonicalSha256().equals(storedResult.resultSha256())
                || !evaluation.inputSnapshotSha256().equals(storedResult.inputSnapshotSha256())
                || !definition.methodologyId().equals(storedResult.methodologyId())
                || definition.version() != storedResult.methodologyVersion()
                || !definition.methodologySha256().equals(storedResult.methodologySha256())) {
            throw new IllegalArgumentException(
                    "Derived risk materialization identities must match exact snapshot and methodology"
            );
        }
    }

    public boolean replayed() {
        return installResult.status() == DerivedRiskResultInstallResult.Status.REPLAYED;
    }
}
