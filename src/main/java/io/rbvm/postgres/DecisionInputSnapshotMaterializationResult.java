package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;

import java.util.Objects;

/** Result of deterministic build followed by immutable V17 installation. */
public record DecisionInputSnapshotMaterializationResult(
        RbvmDecisionInputSnapshot snapshot,
        DecisionInputSnapshotInstallResult installResult
) {
    public DecisionInputSnapshotMaterializationResult {
        snapshot = Objects.requireNonNull(snapshot, "snapshot");
        installResult = Objects.requireNonNull(installResult, "installResult");
        if (!snapshot.snapshotSha256().equals(installResult.requestedSnapshotSha256())) {
            throw new IllegalArgumentException(
                    "Installed Decision Input Snapshot request SHA must match the built snapshot"
            );
        }
    }

    public boolean installedOrReplayed() {
        return installResult.installedOrReplayed();
    }
}
