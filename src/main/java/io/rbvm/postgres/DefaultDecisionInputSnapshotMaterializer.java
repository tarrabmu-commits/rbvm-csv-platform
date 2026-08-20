package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;

import java.io.IOException;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Default build-then-install orchestration with no methodology or scoring inference. */
public final class DefaultDecisionInputSnapshotMaterializer
        implements DecisionInputSnapshotMaterializer {
    private final DecisionInputSnapshotBuilder builder;
    private final DecisionInputSnapshotStore store;

    public DefaultDecisionInputSnapshotMaterializer(
            DecisionInputSnapshotBuilder builder,
            DecisionInputSnapshotStore store
    ) {
        this.builder = Objects.requireNonNull(builder, "builder");
        this.store = Objects.requireNonNull(store, "store");
    }

    @Override
    public DecisionInputSnapshotMaterializationResult materialize(
            UUID findingId,
            int methodologyRevision,
            String methodologyPolicySha256,
            Instant evaluatedAt
    ) throws IOException {
        RbvmDecisionInputSnapshot snapshot = builder.build(
                findingId,
                methodologyRevision,
                methodologyPolicySha256,
                evaluatedAt
        );
        DecisionInputSnapshotInstallResult installResult = store.install(snapshot);
        return new DecisionInputSnapshotMaterializationResult(snapshot, installResult);
    }
}
