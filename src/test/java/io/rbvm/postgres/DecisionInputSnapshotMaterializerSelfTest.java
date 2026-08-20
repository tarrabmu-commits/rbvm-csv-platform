package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;

import java.io.IOException;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public final class DecisionInputSnapshotMaterializerSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final int REVISION = 3;
    private static final String POLICY_SHA = "a".repeat(64);
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-20T04:00:00Z");

    private DecisionInputSnapshotMaterializerSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        buildsThenInstallsAndPreservesOutcomes();
        buildFailurePreventsInstall();
        installFailurePropagatesWithoutRebuild();
        resultRejectsMismatchedRequestedSha();
        System.out.println("DecisionInputSnapshotMaterializerSelfTest: PASS");
    }

    private static void buildsThenInstallsAndPreservesOutcomes() throws Exception {
        RbvmDecisionInputSnapshot snapshot = snapshot();
        RecordingBuilder builder = new RecordingBuilder(snapshot);
        RecordingStore store = new RecordingStore();
        DefaultDecisionInputSnapshotMaterializer materializer =
                new DefaultDecisionInputSnapshotMaterializer(builder, store);

        store.status = DecisionInputSnapshotInstallResult.Status.INSERTED;
        DecisionInputSnapshotMaterializationResult inserted = materializer.materialize(
                FINDING_ID, REVISION, POLICY_SHA, EVALUATED_AT);
        assert inserted.snapshot().equals(snapshot);
        assert inserted.installResult().status()
                == DecisionInputSnapshotInstallResult.Status.INSERTED;
        assert inserted.installedOrReplayed();
        assert builder.calls == 1;
        assert store.calls == 1;
        assert store.lastSnapshot == snapshot;
        assert builder.completedSequence < store.installSequence;

        store.status = DecisionInputSnapshotInstallResult.Status.REPLAYED;
        DecisionInputSnapshotMaterializationResult replayed = materializer.materialize(
                FINDING_ID, REVISION, POLICY_SHA, EVALUATED_AT);
        assert replayed.installResult().status()
                == DecisionInputSnapshotInstallResult.Status.REPLAYED;
        assert replayed.installedOrReplayed();

        store.status = DecisionInputSnapshotInstallResult.Status.EVALUATION_CONFLICT;
        store.conflictExistingSha = "b".repeat(64);
        DecisionInputSnapshotMaterializationResult conflict = materializer.materialize(
                FINDING_ID, REVISION, POLICY_SHA, EVALUATED_AT);
        assert conflict.installResult().status()
                == DecisionInputSnapshotInstallResult.Status.EVALUATION_CONFLICT;
        assert conflict.installResult().requestedSnapshotSha256().equals(snapshot.snapshotSha256());
        assert conflict.installResult().existingSnapshotSha256().equals("b".repeat(64));
        assert !conflict.installedOrReplayed();
    }

    private static void buildFailurePreventsInstall() {
        RecordingBuilder builder = new RecordingBuilder(snapshot());
        builder.fail = true;
        RecordingStore store = new RecordingStore();
        DefaultDecisionInputSnapshotMaterializer materializer =
                new DefaultDecisionInputSnapshotMaterializer(builder, store);

        boolean failed = false;
        try {
            materializer.materialize(FINDING_ID, REVISION, POLICY_SHA, EVALUATED_AT);
        } catch (IOException expected) {
            failed = expected.getMessage().contains("synthetic build failure");
        }
        assert failed;
        assert builder.calls == 1;
        assert store.calls == 0;
    }

    private static void installFailurePropagatesWithoutRebuild() {
        RecordingBuilder builder = new RecordingBuilder(snapshot());
        RecordingStore store = new RecordingStore();
        store.fail = true;
        DefaultDecisionInputSnapshotMaterializer materializer =
                new DefaultDecisionInputSnapshotMaterializer(builder, store);

        boolean failed = false;
        try {
            materializer.materialize(FINDING_ID, REVISION, POLICY_SHA, EVALUATED_AT);
        } catch (IOException expected) {
            failed = expected.getMessage().contains("synthetic install failure");
        }
        assert failed;
        assert builder.calls == 1;
        assert store.calls == 1;
    }

    private static void resultRejectsMismatchedRequestedSha() {
        RbvmDecisionInputSnapshot snapshot = snapshot();
        boolean rejected = false;
        try {
            new DecisionInputSnapshotMaterializationResult(
                    snapshot,
                    new DecisionInputSnapshotInstallResult(
                            DecisionInputSnapshotInstallResult.Status.EVALUATION_CONFLICT,
                            "c".repeat(64),
                            "d".repeat(64)
                    )
            );
        } catch (IllegalArgumentException expected) {
            rejected = expected.getMessage().contains("request SHA");
        }
        assert rejected;
    }

    private static RbvmDecisionInputSnapshot snapshot() {
        EnumMap<EvidenceDimension, DimensionInput> dimensions =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            dimensions.put(
                    dimension,
                    new DimensionInput(dimension, DimensionState.MISSING, List.of())
            );
        }
        return RbvmDecisionInputSnapshot.create(
                FINDING_ID,
                REVISION,
                POLICY_SHA,
                EVALUATED_AT,
                dimensions
        );
    }

    private static final class RecordingBuilder implements DecisionInputSnapshotBuilder {
        private static int sequence;
        private final RbvmDecisionInputSnapshot snapshot;
        private int calls;
        private int completedSequence;
        private boolean fail;

        private RecordingBuilder(RbvmDecisionInputSnapshot snapshot) {
            this.snapshot = snapshot;
        }

        @Override
        public RbvmDecisionInputSnapshot build(
                UUID findingId,
                int methodologyRevision,
                String methodologyPolicySha256,
                Instant evaluatedAt
        ) throws IOException {
            calls++;
            assert findingId.equals(FINDING_ID);
            assert methodologyRevision == REVISION;
            assert methodologyPolicySha256.equals(POLICY_SHA);
            assert evaluatedAt.equals(EVALUATED_AT);
            if (fail) throw new IOException("synthetic build failure");
            completedSequence = ++sequence;
            return snapshot;
        }
    }

    private static final class RecordingStore implements DecisionInputSnapshotStore {
        private int calls;
        private int installSequence;
        private boolean fail;
        private RbvmDecisionInputSnapshot lastSnapshot;
        private DecisionInputSnapshotInstallResult.Status status =
                DecisionInputSnapshotInstallResult.Status.INSERTED;
        private String conflictExistingSha = "b".repeat(64);

        @Override
        public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot snapshot)
                throws IOException {
            calls++;
            installSequence = ++RecordingBuilder.sequence;
            lastSnapshot = snapshot;
            if (fail) throw new IOException("synthetic install failure");
            String existing = status == DecisionInputSnapshotInstallResult.Status.EVALUATION_CONFLICT
                    ? conflictExistingSha
                    : snapshot.snapshotSha256();
            return new DecisionInputSnapshotInstallResult(
                    status,
                    snapshot.snapshotSha256(),
                    existing
            );
        }

        @Override
        public Optional<RbvmDecisionInputSnapshot> findBySha256(String snapshotSha256) {
            return Optional.empty();
        }
    }
}
