package io.rbvm.postgres;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

/** Builds and immutably installs one policy-bound Decision Input Snapshot. */
@FunctionalInterface
public interface DecisionInputSnapshotMaterializer {
    DecisionInputSnapshotMaterializationResult materialize(
            UUID findingId,
            int methodologyRevision,
            String methodologyPolicySha256,
            Instant evaluatedAt
    ) throws IOException;
}
