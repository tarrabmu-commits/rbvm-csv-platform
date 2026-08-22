package io.rbvm.csv;

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
import io.rbvm.postgres.DecisionInputSnapshotInstallResult;
import io.rbvm.postgres.DecisionInputSnapshotStore;
import io.rbvm.postgres.DefaultDerivedRiskResultMaterializer;
import io.rbvm.postgres.DerivedRiskResultInstallResult;
import io.rbvm.postgres.DerivedRiskResultReplayVerifier;
import io.rbvm.postgres.DerivedRiskResultStore;
import io.rbvm.postgres.StoredDerivedRiskResult;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/** Pure contract coverage for catalog, exact reads, and explicit materialization. */
public final class DerivedRiskResultApiSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static final String POLICY_SHA = "f".repeat(64);
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T21:30:00Z");
    private static final Instant PERSISTED_AT = Instant.parse("2026-08-22T21:30:05Z");

    private DerivedRiskResultApiSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesCatalogWithoutDefaultSemantics();
        materializesAndReadsExactMethodologyIdentities();
        rejectsInvalidMissingAndNonCanonicalMethodologyIdentities();
        System.out.println("DerivedRiskResultApiSelfTest: PASS");
    }

    private static void exposesCatalogWithoutDefaultSemantics() {
        Fixture fixture = fixture();
        DerivedRiskResultApi.Response response = fixture.api().listMethodologies();
        assert response.status() == 200;
        assert response.body().get("contractId").equals(DerivedRiskResultApi.CATALOG_CONTRACT_ID);
        assert response.body().get("selectionSemantics")
                .equals("EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> definitions =
                (List<Map<String, Object>>) response.body().get("methodologies");
        assert definitions.size() == 2;
        assert definitions.stream().map(value -> value.get("methodologyId")).toList()
                .equals(List.of(
                        MicrosoftProbabilityDamageDerivedV1.METHODOLOGY_ID,
                        OwaspDerivedRiskV1.METHODOLOGY_ID
                ));
        assert definitions.stream().noneMatch(value ->
                value.containsKey("default") || value.containsKey("preferred"));
    }

    private static void materializesAndReadsExactMethodologyIdentities() throws Exception {
        Fixture fixture = fixture();
        DerivedRiskResultApi api = fixture.api();
        RbvmDecisionInputSnapshot snapshot = fixture.snapshot();

        DerivedRiskResultApi.Response inserted = api.materialize(
                snapshot.snapshotSha256(),
                OwaspDerivedRiskV1.METHODOLOGY_ID,
                OwaspDerivedRiskV1.METHODOLOGY_SHA256
        );
        assert inserted.status() == 201;
        assert inserted.body().get("contractId")
                .equals(DerivedRiskResultApi.MATERIALIZATION_CONTRACT_ID);
        assert inserted.body().get("materializationStatus").equals("INSERTED");
        assert inserted.body().get("resultState").equals("NON_COMPUTABLE");
        assert inserted.body().get("reasonCode").equals("APPLICABILITY_MISSING");
        assert inserted.body().get("numericScore") == null;
        assert inserted.body().get("rating") == null;
        String owaspResultSha = (String) inserted.body().get("resultSha256");
        assert inserted.headers().get("ETag").equals(DerivedRiskResultApi.strongEtag(owaspResultSha));
        assert inserted.headers().get("Location")
                .equals("/api/v1/derived-risk-results/" + owaspResultSha);

        DerivedRiskResultApi.Response replayed = api.materialize(
                snapshot.snapshotSha256(),
                OwaspDerivedRiskV1.METHODOLOGY_ID,
                OwaspDerivedRiskV1.METHODOLOGY_SHA256
        );
        assert replayed.status() == 200;
        assert replayed.body().get("materializationStatus").equals("REPLAYED");
        assert replayed.body().get("resultSha256").equals(owaspResultSha);

        DerivedRiskResultApi.Response microsoft = api.materialize(
                snapshot.snapshotSha256(),
                MicrosoftProbabilityDamageDerivedV1.METHODOLOGY_ID,
                MicrosoftProbabilityDamageDerivedV1.METHODOLOGY_SHA256
        );
        assert microsoft.status() == 201;
        assert !microsoft.body().get("resultSha256").equals(owaspResultSha);
        assert fixture.store().size() == 2;

        DerivedRiskResultApi.Response bySha = api.getByResultSha256(owaspResultSha);
        assert bySha.status() == 200;
        assert bySha.body().get("contractId").equals(DerivedRiskResultApi.CONTRACT_ID);
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) bySha.body().get("result");
        assert result.get("inputSnapshotSha256").equals(snapshot.snapshotSha256());
        assert result.get("findingId").equals(FINDING_ID.toString());
        assert result.get("resultState").equals("NON_COMPUTABLE");
        @SuppressWarnings("unchecked")
        Map<String, Object> methodology = (Map<String, Object>) result.get("methodology");
        assert methodology.get("methodologyId").equals(OwaspDerivedRiskV1.METHODOLOGY_ID);
        assert methodology.get("methodologySha256").equals(OwaspDerivedRiskV1.METHODOLOGY_SHA256);

        @SuppressWarnings("unchecked")
        Map<String, Object> canonical =
                (Map<String, Object>) bySha.body().get("canonicalResult");
        assert Boolean.TRUE.equals(canonical.get("replayVerified"));
        assert canonical.get("sha256").equals(owaspResultSha);
        StoredDerivedRiskResult stored = fixture.store().findByResultSha256(owaspResultSha).orElseThrow();
        assert java.util.Arrays.equals(
                Base64.getDecoder().decode((String) canonical.get("canonicalPayloadBase64")),
                stored.canonicalPayload()
        );

        DerivedRiskResultApi.Response byIdentity = api.getByInputSnapshotAndMethodology(
                snapshot.snapshotSha256(),
                OwaspDerivedRiskV1.METHODOLOGY_ID,
                OwaspDerivedRiskV1.METHODOLOGY_SHA256
        );
        assert byIdentity.status() == 200;
        assert byIdentity.headers().get("ETag")
                .equals(DerivedRiskResultApi.strongEtag(owaspResultSha));
    }

    private static void rejectsInvalidMissingAndNonCanonicalMethodologyIdentities()
            throws Exception {
        Fixture fixture = fixture();
        DerivedRiskResultApi api = fixture.api();

        boolean invalidSha = false;
        try {
            api.getByResultSha256("ABC");
        } catch (DerivedRiskResultApi.ApiProblem expected) {
            invalidSha = expected.status() == 400
                    && expected.code().equals("INVALID_DERIVED_RISK_IDENTITY");
        }
        assert invalidSha;

        boolean missingResult = false;
        try {
            api.getByResultSha256("0".repeat(64));
        } catch (DerivedRiskResultApi.ApiProblem expected) {
            missingResult = expected.status() == 404
                    && expected.code().equals("DERIVED_RISK_RESULT_NOT_FOUND");
        }
        assert missingResult;

        boolean unknownMethodology = false;
        try {
            api.materialize(fixture.snapshot().snapshotSha256(), "NOT_IMPLEMENTED", "1".repeat(64));
        } catch (DerivedRiskResultApi.ApiProblem expected) {
            unknownMethodology = expected.status() == 404
                    && expected.code().equals("DERIVED_RISK_METHODOLOGY_NOT_FOUND");
        }
        assert unknownMethodology;

        boolean wrongSha = false;
        try {
            api.materialize(
                    fixture.snapshot().snapshotSha256(),
                    OwaspDerivedRiskV1.METHODOLOGY_ID,
                    "1".repeat(64)
            );
        } catch (DerivedRiskResultApi.ApiProblem expected) {
            wrongSha = expected.status() == 404
                    && expected.code().equals("DERIVED_RISK_METHODOLOGY_NOT_FOUND");
        }
        assert wrongSha;

        boolean nonCanonicalId = false;
        try {
            api.materialize(
                    fixture.snapshot().snapshotSha256(),
                    "owasp_derived_rbvm_v1",
                    OwaspDerivedRiskV1.METHODOLOGY_SHA256
            );
        } catch (DerivedRiskResultApi.ApiProblem expected) {
            nonCanonicalId = expected.status() == 404
                    && expected.code().equals("DERIVED_RISK_METHODOLOGY_NOT_FOUND");
        }
        assert nonCanonicalId : "API identity must require the canonical methodology ID";
    }

    private static Fixture fixture() {
        EnumMap<EvidenceDimension, DimensionInput> dimensions =
                new EnumMap<>(EvidenceDimension.class);
        EnumMap<EvidenceDimension, List<ResolvedEvidence>> values =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            dimensions.put(dimension, new DimensionInput(dimension, DimensionState.MISSING, List.of()));
            values.put(dimension, List.of());
        }
        RbvmDecisionInputSnapshot snapshot = RbvmDecisionInputSnapshot.createV3(
                FINDING_ID,
                1,
                POLICY_SHA,
                EVALUATED_AT,
                dimensions
        );
        RbvmResolvedDecisionInput resolved = new RbvmResolvedDecisionInput(snapshot, Map.copyOf(values));
        InMemorySnapshotStore snapshots = new InMemorySnapshotStore(snapshot);
        InMemoryResultStore results = new InMemoryResultStore();
        DecisionInputEvidenceResolver resolver = candidate -> {
            assert candidate.snapshotSha256().equals(snapshot.snapshotSha256());
            return resolved;
        };
        DerivedRiskResultReplayVerifier replay = new DerivedRiskResultReplayVerifier(
                results,
                snapshots,
                resolver
        );
        DefaultDerivedRiskResultMaterializer materializer = new DefaultDerivedRiskResultMaterializer(
                snapshots,
                resolver,
                results,
                replay
        );
        return new Fixture(
                snapshot,
                results,
                new DerivedRiskResultApi(results, replay, materializer)
        );
    }

    private static StoredDerivedRiskResult stored(RbvmDerivedRiskCanonicalResult canonical) {
        var evaluation = canonical.evaluation();
        var definition = evaluation.definition();
        return new StoredDerivedRiskResult(
                UUID.nameUUIDFromBytes(
                        canonical.canonicalSha256().getBytes(StandardCharsets.UTF_8)
                ),
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
                PERSISTED_AT
        );
    }

    private record Fixture(
            RbvmDecisionInputSnapshot snapshot,
            InMemoryResultStore store,
            DerivedRiskResultApi api
    ) {
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

        private static String key(String snapshotSha, String methodologyId, String methodologySha) {
            return snapshotSha + ":" + methodologyId + ":" + methodologySha;
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
