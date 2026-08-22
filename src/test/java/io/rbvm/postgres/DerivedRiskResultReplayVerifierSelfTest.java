package io.rbvm.postgres;

import io.rbvm.decision.DecisionInputEvidenceResolver;
import io.rbvm.decision.OwaspDerivedRiskV1;
import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDerivedRiskCanonicalResult;
import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmResolvedDecisionInput;
import io.rbvm.decision.RbvmResolvedDecisionInput.ResolvedEvidence;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** Pure acceptance coverage for exact derived-risk persistence identity and historical replay. */
public final class DerivedRiskResultReplayVerifierSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("77777777-7777-4777-8777-777777777777");
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T20:30:00Z");
    private static final String POLICY_SHA = "c".repeat(64);

    private DerivedRiskResultReplayVerifierSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exactTerminalResultReplaysByteIdentically();
        unavailableResultFailsClosed();
        System.out.println("DerivedRiskResultReplayVerifierSelfTest: PASS");
    }

    private static void exactTerminalResultReplaysByteIdentically() throws Exception {
        RbvmDecisionInputSnapshot snapshot = missingSnapshot();
        RbvmResolvedDecisionInput resolved = missingResolved(snapshot);
        RbvmDerivedRiskMethodology.Evaluation evaluation =
                OwaspDerivedRiskV1.INSTANCE.evaluate(resolved);
        assert evaluation.state() == RbvmDerivedRiskMethodology.ResultState.NON_COMPUTABLE;
        assert evaluation.reasonCode().equals("APPLICABILITY_MISSING");

        RbvmDerivedRiskCanonicalResult canonical = RbvmDerivedRiskCanonicalResult.from(evaluation);
        StoredDerivedRiskResult stored = stored(canonical);
        InMemoryResultStore resultStore = new InMemoryResultStore(stored);
        DecisionInputSnapshotStore snapshotStore = new InMemorySnapshotStore(snapshot);
        DecisionInputEvidenceResolver resolver = candidate -> {
            assert candidate.snapshotSha256().equals(snapshot.snapshotSha256());
            return resolved;
        };
        DerivedRiskResultReplayVerifier verifier = new DerivedRiskResultReplayVerifier(
                resultStore,
                snapshotStore,
                resolver
        );

        RbvmDerivedRiskCanonicalResult replayed = verifier.replay(stored);
        assert replayed.canonicalSha256().equals(canonical.canonicalSha256());
        assert Arrays.equals(replayed.canonicalPayload(), canonical.canonicalPayload());
        assert verifier.verifyByResultSha256(canonical.canonicalSha256()) == stored;
        assert verifier.verifyBySnapshotAndMethodology(
                snapshot.snapshotSha256(),
                evaluation.definition().methodologyId(),
                evaluation.definition().methodologySha256()
        ) == stored;
    }

    private static void unavailableResultFailsClosed() throws Exception {
        RbvmDecisionInputSnapshot snapshot = missingSnapshot();
        DerivedRiskResultReplayVerifier verifier = new DerivedRiskResultReplayVerifier(
                new InMemoryResultStore(null),
                new InMemorySnapshotStore(snapshot),
                candidate -> missingResolved(candidate)
        );
        boolean rejected = false;
        try {
            verifier.verifyByResultSha256("d".repeat(64));
        } catch (IOException expected) {
            rejected = expected.getMessage().contains("does not exist");
        }
        assert rejected;
    }

    private static RbvmDecisionInputSnapshot missingSnapshot() {
        EnumMap<EvidenceDimension, DimensionInput> dimensions =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            dimensions.put(
                    dimension,
                    new DimensionInput(dimension, DimensionState.MISSING, List.of())
            );
        }
        return RbvmDecisionInputSnapshot.createV3(
                FINDING_ID,
                1,
                POLICY_SHA,
                EVALUATED_AT,
                dimensions
        );
    }

    private static RbvmResolvedDecisionInput missingResolved(RbvmDecisionInputSnapshot snapshot) {
        EnumMap<EvidenceDimension, List<ResolvedEvidence>> evidence =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            evidence.put(dimension, List.of());
        }
        return new RbvmResolvedDecisionInput(snapshot, Map.copyOf(evidence));
    }

    private static StoredDerivedRiskResult stored(RbvmDerivedRiskCanonicalResult canonical) {
        RbvmDerivedRiskMethodology.Evaluation evaluation = canonical.evaluation();
        RbvmDerivedRiskMethodology.Definition definition = evaluation.definition();
        return new StoredDerivedRiskResult(
                UUID.fromString("88888888-8888-4888-8888-888888888888"),
                evaluation.inputSnapshotSha256(),
                evaluation.findingId(),
                definition.methodologyId(),
                definition.version(),
                definition.methodologySha256(),
                evaluation.state(),
                evaluation.reasonCode(),
                evaluation.numericScore(),
                evaluation.numericScale(),
                evaluation.rating(),
                RbvmDerivedRiskCanonicalResult.PAYLOAD_FORMAT,
                canonical.canonicalSha256(),
                canonical.canonicalPayload(),
                Instant.parse("2026-08-22T20:31:00Z")
        );
    }

    private static final class InMemoryResultStore implements DerivedRiskResultStore {
        private final StoredDerivedRiskResult value;

        private InMemoryResultStore(StoredDerivedRiskResult value) {
            this.value = value;
        }

        @Override
        public DerivedRiskResultInstallResult install(RbvmDerivedRiskCanonicalResult result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<StoredDerivedRiskResult> findByResultSha256(String resultSha256) {
            if (value != null && value.resultSha256().equals(resultSha256)) {
                return Optional.of(value);
            }
            return Optional.empty();
        }

        @Override
        public Optional<StoredDerivedRiskResult> findBySnapshotAndMethodology(
                String inputSnapshotSha256,
                String methodologyId,
                String methodologySha256
        ) {
            if (value != null
                    && value.inputSnapshotSha256().equals(inputSnapshotSha256)
                    && value.methodologyId().equals(methodologyId)
                    && value.methodologySha256().equals(methodologySha256)) {
                return Optional.of(value);
            }
            return Optional.empty();
        }
    }

    private static final class InMemorySnapshotStore implements DecisionInputSnapshotStore {
        private final RbvmDecisionInputSnapshot snapshot;

        private InMemorySnapshotStore(RbvmDecisionInputSnapshot snapshot) {
            this.snapshot = snapshot;
        }

        @Override
        public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot value) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<RbvmDecisionInputSnapshot> findBySha256(String snapshotSha256) {
            return snapshot.snapshotSha256().equals(snapshotSha256)
                    ? Optional.of(snapshot)
                    : Optional.empty();
        }
    }
}
