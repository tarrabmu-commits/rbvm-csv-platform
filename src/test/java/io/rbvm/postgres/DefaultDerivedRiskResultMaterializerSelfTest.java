package io.rbvm.postgres;

import io.rbvm.decision.DecisionInputEvidenceResolver;
import io.rbvm.decision.MicrosoftProbabilityDamageDerivedV1;
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
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** Acceptance checks for exact snapshot + explicit methodology production materialization. */
public final class DefaultDerivedRiskResultMaterializerSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("99999999-9999-4999-8999-999999999999");
    private static final String POLICY_SHA = "e".repeat(64);

    private DefaultDerivedRiskResultMaterializerSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        materializesTwoExplicitMethodologiesWithoutDefault();
        rejectsUnknownOrMismatchedMethodologyIdentity();
        rejectsMissingSnapshot();
        System.out.println("DefaultDerivedRiskResultMaterializerSelfTest: PASS");
    }

    private static void materializesTwoExplicitMethodologiesWithoutDefault() throws Exception {
        RbvmDecisionInputSnapshot snapshot = missingSnapshot();
        RbvmResolvedDecisionInput resolved = missingResolved(snapshot);
        InMemoryResultStore resultStore = new InMemoryResultStore();
        DecisionInputEvidenceResolver resolver = candidate -> {
            assert candidate.snapshotSha256().equals(snapshot.snapshotSha256());
            return resolved;
        };
        DerivedRiskResultReplayVerifier replay = new DerivedRiskResultReplayVerifier(
                resultStore,
                new InMemorySnapshotStore(snapshot),
                resolver
        );
        DefaultDerivedRiskResultMaterializer materializer = new DefaultDerivedRiskResultMaterializer(
                new InMemorySnapshotStore(snapshot),
                resolver,
                resultStore,
                replay
        );

        DerivedRiskResultMaterializationResult owasp = materializer.materialize(
                snapshot.snapshotSha256(),
                OwaspDerivedRiskV1.METHODOLOGY_ID,
                OwaspDerivedRiskV1.METHODOLOGY_SHA256
        );
        assert owasp.installResult().status() == DerivedRiskResultInstallResult.Status.INSERTED;
        assert owasp.canonicalResult().evaluation().definition().methodologyId()
                .equals(OwaspDerivedRiskV1.METHODOLOGY_ID);
        assert owasp.canonicalResult().evaluation().state()
                == RbvmDerivedRiskMethodology.ResultState.NON_COMPUTABLE;

        DerivedRiskResultMaterializationResult owaspReplay = materializer.materialize(
                snapshot.snapshotSha256(),
                OwaspDerivedRiskV1.METHODOLOGY_ID,
                OwaspDerivedRiskV1.METHODOLOGY_SHA256
        );
        assert owaspReplay.replayed();
        assert owaspReplay.canonicalResult().canonicalSha256()
                .equals(owasp.canonicalResult().canonicalSha256());

        DerivedRiskResultMaterializationResult microsoft = materializer.materialize(
                snapshot.snapshotSha256(),
                MicrosoftProbabilityDamageDerivedV1.METHODOLOGY_ID,
                MicrosoftProbabilityDamageDerivedV1.METHODOLOGY_SHA256
        );
        assert microsoft.installResult().status() == DerivedRiskResultInstallResult.Status.INSERTED;
        assert microsoft.canonicalResult().evaluation().definition().methodologyId()
                .equals(MicrosoftProbabilityDamageDerivedV1.METHODOLOGY_ID);
        assert !microsoft.canonicalResult().canonicalSha256()
                .equals(owasp.canonicalResult().canonicalSha256());
        assert resultStore.size() == 2;
    }

    private static void rejectsUnknownOrMismatchedMethodologyIdentity() throws Exception {
        RbvmDecisionInputSnapshot snapshot = missingSnapshot();
        RbvmResolvedDecisionInput resolved = missingResolved(snapshot);
        InMemoryResultStore resultStore = new InMemoryResultStore();
        DefaultDerivedRiskResultMaterializer materializer = materializer(snapshot, resolved, resultStore);

        boolean unknownRejected = false;
        try {
            materializer.materialize(snapshot.snapshotSha256(), "NOT_IMPLEMENTED", "a".repeat(64));
        } catch (DefaultDerivedRiskResultMaterializer.MethodologyNotFoundException expected) {
            unknownRejected = true;
        }
        assert unknownRejected;
        assert resultStore.size() == 0;

        boolean mismatchRejected = false;
        try {
            materializer.materialize(
                    snapshot.snapshotSha256(),
                    OwaspDerivedRiskV1.METHODOLOGY_ID,
                    "a".repeat(64)
            );
        } catch (DefaultDerivedRiskResultMaterializer.MethodologyIdentityMismatchException expected) {
            mismatchRejected = true;
        }
        assert mismatchRejected;
        assert resultStore.size() == 0;
    }

    private static void rejectsMissingSnapshot() throws Exception {
        RbvmDecisionInputSnapshot snapshot = missingSnapshot();
        InMemoryResultStore resultStore = new InMemoryResultStore();
        DecisionInputSnapshotStore missing = new DecisionInputSnapshotStore() {
            @Override
            public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot value) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Optional<RbvmDecisionInputSnapshot> findBySha256(String snapshotSha256) {
                return Optional.empty();
            }
        };
        DefaultDerivedRiskResultMaterializer materializer = new DefaultDerivedRiskResultMaterializer(
                missing,
                candidate -> missingResolved(candidate),
                resultStore,
                new DerivedRiskResultReplayVerifier(
                        resultStore,
                        missing,
                        candidate -> missingResolved(candidate)
                )
        );
        boolean rejected = false;
        try {
            materializer.materialize(
                    snapshot.snapshotSha256(),
                    OwaspDerivedRiskV1.METHODOLOGY_ID,
                    OwaspDerivedRiskV1.METHODOLOGY_SHA256
            );
        } catch (DefaultDerivedRiskResultMaterializer.SnapshotNotFoundException expected) {
            rejected = true;
        }
        assert rejected;
    }

    private static DefaultDerivedRiskResultMaterializer materializer(
            RbvmDecisionInputSnapshot snapshot,
            RbvmResolvedDecisionInput resolved,
            InMemoryResultStore resultStore
    ) {
        InMemorySnapshotStore snapshotStore = new InMemorySnapshotStore(snapshot);
        DecisionInputEvidenceResolver resolver = candidate -> resolved;
        return new DefaultDerivedRiskResultMaterializer(
                snapshotStore,
                resolver,
                resultStore,
                new DerivedRiskResultReplayVerifier(resultStore, snapshotStore, resolver)
        );
    }

    private static RbvmDecisionInputSnapshot missingSnapshot() {
        EnumMap<EvidenceDimension, DimensionInput> dimensions =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            dimensions.put(dimension, new DimensionInput(dimension, DimensionState.MISSING, List.of()));
        }
        return RbvmDecisionInputSnapshot.createV3(
                FINDING_ID,
                1,
                POLICY_SHA,
                Instant.parse("2026-08-22T21:00:00Z"),
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
        var evaluation = canonical.evaluation();
        var definition = evaluation.definition();
        return new StoredDerivedRiskResult(
                UUID.nameUUIDFromBytes(canonical.canonicalSha256().getBytes()),
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
                Instant.parse("2026-08-22T21:01:00Z")
        );
    }

    private static final class InMemoryResultStore implements DerivedRiskResultStore {
        private final Map<String, StoredDerivedRiskResult> bySha = new HashMap<>();
        private final Map<String, StoredDerivedRiskResult> byIdentity = new HashMap<>();

        @Override
        public DerivedRiskResultInstallResult install(RbvmDerivedRiskCanonicalResult canonical) {
            var evaluation = canonical.evaluation();
            var definition = evaluation.definition();
            String key = key(
                    evaluation.inputSnapshotSha256(),
                    definition.methodologyId(),
                    definition.methodologySha256()
            );
            StoredDerivedRiskResult existing = byIdentity.get(key);
            if (existing != null) {
                boolean replay = existing.resultSha256().equals(canonical.canonicalSha256());
                return new DerivedRiskResultInstallResult(
                        replay
                                ? DerivedRiskResultInstallResult.Status.REPLAYED
                                : DerivedRiskResultInstallResult.Status.RESULT_CONFLICT,
                        canonical.canonicalSha256(),
                        existing.resultSha256()
                );
            }
            StoredDerivedRiskResult value = stored(canonical);
            byIdentity.put(key, value);
            bySha.put(value.resultSha256(), value);
            return new DerivedRiskResultInstallResult(
                    DerivedRiskResultInstallResult.Status.INSERTED,
                    canonical.canonicalSha256(),
                    canonical.canonicalSha256()
            );
        }

        @Override
        public Optional<StoredDerivedRiskResult> findByResultSha256(String resultSha256) {
            return Optional.ofNullable(bySha.get(resultSha256));
        }

        @Override
        public Optional<StoredDerivedRiskResult> findBySnapshotAndMethodology(
                String inputSnapshotSha256,
                String methodologyId,
                String methodologySha256
        ) {
            return Optional.ofNullable(byIdentity.get(
                    key(inputSnapshotSha256, methodologyId, methodologySha256)
            ));
        }

        int size() {
            return bySha.size();
        }

        private static String key(String snapshot, String id, String sha) {
            return snapshot + ":" + id + ":" + sha;
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
