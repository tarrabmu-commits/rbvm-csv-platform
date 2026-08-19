package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;

import java.io.IOException;
import java.util.Optional;

/** Immutable persistence boundary for policy-bound RBVM decision input snapshots. */
public interface DecisionInputSnapshotStore {
    DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot snapshot) throws IOException;

    Optional<RbvmDecisionInputSnapshot> findBySha256(String snapshotSha256) throws IOException;
}
