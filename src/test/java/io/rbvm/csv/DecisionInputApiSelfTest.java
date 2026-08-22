package io.rbvm.csv;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy;
import io.rbvm.postgres.DecisionInputRuntimeAccess;
import io.rbvm.postgres.DecisionInputSnapshotInstallResult;
import io.rbvm.postgres.DecisionInputSnapshotMaterializationResult;
import io.rbvm.postgres.DecisionInputSnapshotStore;
import io.rbvm.postgres.DecisionMethodologyPolicyInstallResult;
import io.rbvm.postgres.DecisionMethodologyPolicyStore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.AmbiguityHandling.PRESERVE_AMBIGUOUS;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.FreshnessMode.NO_AGE_LIMIT;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.LegacyPriorityHandling.EXCLUDE_LEGACY_PRIORITY_TIER;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.MissingEvidenceHandling.PRESERVE_UNKNOWN;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.SourceSelectionMode.ALL_SOURCES;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.SubjectScope.FINDING;

public final class DecisionInputApiSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("a1111111-1111-4111-8111-111111111111");
    private static final Instant FIRST_EVALUATED_AT =
            Instant.parse("2026-08-22T16:00:00Z");
    private static final Instant SECOND_EVALUATED_AT =
            Instant.parse("2026-08-22T17:00:00Z");

    private DecisionInputApiSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        readsExactSnapshotAndPreservesUnknownStates();
        exposesHistoryAndMethodologyCatalogWithoutPrecedence();
        materializesOnlyFromExplicitIdentityAndReplaysIdempotently();
        rejectsInvalidMaterializationRequests();
        System.out.println("DecisionInputApiSelfTest: PASS");
    }

    private static void readsExactSnapshotAndPreservesUnknownStates() throws Exception {
        Fixture fixture = fixture();
        DecisionInputApi.Response response = fixture.api().getSnapshot(
                fixture.second().snapshotSha256()
        );
        assert response.status() == 200;
        assert response.headers().get("ETag").equals(
                DecisionInputApi.strongEtag(fixture.second().snapshotSha256())
        );
        assert response.body().get("contractId").equals(DecisionInputApi.CONTRACT_ID);

        @SuppressWarnings("unchecked")
        Map<String, Object> snapshot = (Map<String, Object>) response.body().get("snapshot");
        assert snapshot.get("contractId").equals(RbvmDecisionInputSnapshot.V3_ID);
        assert snapshot.get("snapshotSha256").equals(fixture.second().snapshotSha256());
        assert snapshot.get("findingId").equals(FINDING_ID.toString());
        assert snapshot.get("evaluatedAt").equals(SECOND_EVALUATED_AT.toString());
        assert snapshot.get("methodologyPolicySha256").equals(fixture.policy().policySha256());
        assert snapshot.get("canonicalPayloadBase64") instanceof String;

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> dimensions =
                (List<Map<String, Object>>) snapshot.get("dimensions");
        assert dimensions.size() == EvidenceDimension.values().length;
        assert dimensions.stream().allMatch(row -> row.get("state").equals("MISSING"));
        assert dimensions.stream().allMatch(row ->
                ((List<?>) row.get("evidenceReferences")).isEmpty());
    }

    private static void exposesHistoryAndMethodologyCatalogWithoutPrecedence() throws Exception {
        Fixture fixture = fixture();
        DecisionInputApi.Response history = fixture.api().history(
                FINDING_ID,
                1,
                null,
                null
        );
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> snapshots =
                (List<Map<String, Object>>) history.body().get("snapshots");
        assert snapshots.size() == 1;
        assert snapshots.get(0).get("snapshotSha256").equals(fixture.second().snapshotSha256());
        assert history.body().get("nextBeforeEvaluatedAt").equals(SECOND_EVALUATED_AT.toString());
        assert history.body().get("nextBeforeSnapshotSha256")
                .equals(fixture.second().snapshotSha256());
        assert !history.body().containsKey("current");
        assert !history.body().containsKey("latest");

        DecisionInputApi.Response methodologies = fixture.api().methodologies(10, null);
        assert methodologies.body().get("orderingSemantics").equals(
                "REVISION_ASCENDING_FOR_PAGINATION_ONLY_NO_PRECEDENCE_OR_PREFERENCE"
        );
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> policies =
                (List<Map<String, Object>>) methodologies.body().get("methodologies");
        assert policies.size() == 1;
        assert policies.get(0).get("revision").equals(fixture.policy().revision());
        assert policies.get(0).get("policySha256").equals(fixture.policy().policySha256());
        assert !policies.get(0).containsKey("preferred");
        assert !policies.get(0).containsKey("current");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> evidencePolicies =
                (List<Map<String, Object>>) policies.get(0).get("evidencePolicies");
        assert evidencePolicies.size() == EvidenceDimension.values().length;
    }

    private static void materializesOnlyFromExplicitIdentityAndReplaysIdempotently()
            throws Exception {
        Fixture fixture = fixture();
        String body = materializationBody(fixture.policy());

        DecisionInputApi.Response first = fixture.api().materialize(
                "application/json; charset=utf-8",
                bytes(body)
        );
        DecisionInputApi.Response replay = fixture.api().materialize(
                "application/json",
                bytes(body)
        );

        assert first.status() == 201;
        assert replay.status() == 200;
        assert first.body().get("materializationStatus").equals("INSERTED");
        assert replay.body().get("materializationStatus").equals("REPLAYED");
        assert first.headers().get("Location").equals(
                "/api/v1/decision-input-snapshots/" + fixture.second().snapshotSha256()
        );
        assert first.headers().get("ETag").equals(
                DecisionInputApi.strongEtag(fixture.second().snapshotSha256())
        );
        assert fixture.materializations().get() == 2;
    }

    private static void rejectsInvalidMaterializationRequests() throws Exception {
        Fixture fixture = fixture();
        assertProblem(
                () -> fixture.api().materialize("text/plain", bytes("{}")),
                415,
                "UNSUPPORTED_MEDIA_TYPE"
        );
        assertProblem(
                () -> fixture.api().materialize(
                        "application/json",
                        bytes(materializationBody(fixture.policy()).replace(
                                "\"evaluatedAt\":\"2026-08-22T17:00:00Z\"",
                                "\"evaluatedAt\":\"2026-08-22T17:00:00.000Z\""
                        ))
                ),
                422,
                "DECISION_INPUT_MATERIALIZATION_REJECTED"
        );
        assertProblem(
                () -> fixture.api().materialize(
                        "application/json",
                        bytes(materializationBody(fixture.policy()).replace(
                                "\"methodologyPolicySha256\":\"" + fixture.policy().policySha256() + "\"",
                                "\"methodologyPolicySha256\":\"" + "f".repeat(64) + "\""
                        ))
                ),
                409,
                "DECISION_METHODOLOGY_IDENTITY_MISMATCH"
        );
        assertProblem(
                () -> fixture.api().materialize(
                        "application/json",
                        bytes(materializationBody(fixture.policy()).replace(
                                "}",
                                ",\"latest\":true}"
                        ))
                ),
                400,
                "UNKNOWN_DECISION_INPUT_MATERIALIZATION_FIELDS"
        );
        assertProblem(
                () -> fixture.api().getSnapshot("ABC"),
                400,
                "INVALID_DECISION_INPUT_IDENTITY"
        );
        assertProblem(
                () -> fixture.api().getSnapshot("0".repeat(64)),
                404,
                "DECISION_INPUT_SNAPSHOT_NOT_FOUND"
        );
    }

    private static Fixture fixture() {
        RbvmDecisionMethodologyPolicy policy = policy();
        RbvmDecisionInputSnapshot first = snapshot(policy, FIRST_EVALUATED_AT);
        RbvmDecisionInputSnapshot second = snapshot(policy, SECOND_EVALUATED_AT);
        Map<String, RbvmDecisionInputSnapshot> stored = new java.util.LinkedHashMap<>();
        stored.put(first.snapshotSha256(), first);
        stored.put(second.snapshotSha256(), second);

        DecisionMethodologyPolicyStore methodologyStore = new DecisionMethodologyPolicyStore() {
            @Override
            public DecisionMethodologyPolicyInstallResult install(
                    RbvmDecisionMethodologyPolicy ignored
            ) {
                throw new UnsupportedOperationException("not used by API test");
            }

            @Override
            public Optional<RbvmDecisionMethodologyPolicy> findByRevision(int revision) {
                return revision == policy.revision() ? Optional.of(policy) : Optional.empty();
            }
        };
        DecisionInputSnapshotStore snapshotStore = new DecisionInputSnapshotStore() {
            @Override
            public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot ignored) {
                throw new UnsupportedOperationException("not used by API test");
            }

            @Override
            public Optional<RbvmDecisionInputSnapshot> findBySha256(String sha) {
                return Optional.ofNullable(stored.get(sha));
            }
        };
        AtomicInteger materializations = new AtomicInteger();
        DecisionInputRuntimeAccess runtime = new DecisionInputRuntimeAccess(
                methodologyStore,
                snapshotStore,
                (findingId, revision, policySha, evaluatedAt) -> {
                    assert findingId.equals(FINDING_ID);
                    assert revision == policy.revision();
                    assert policySha.equals(policy.policySha256());
                    assert evaluatedAt.equals(SECOND_EVALUATED_AT);
                    DecisionInputSnapshotInstallResult.Status status =
                            materializations.getAndIncrement() == 0
                                    ? DecisionInputSnapshotInstallResult.Status.INSERTED
                                    : DecisionInputSnapshotInstallResult.Status.REPLAYED;
                    return new DecisionInputSnapshotMaterializationResult(
                            second,
                            new DecisionInputSnapshotInstallResult(
                                    status,
                                    second.snapshotSha256(),
                                    second.snapshotSha256()
                            )
                    );
                },
                (findingId, limit, beforeAt, beforeSha) -> {
                    assert findingId.equals(FINDING_ID);
                    if (beforeAt == null) {
                        if (limit == 1) {
                            return new DecisionInputRuntimeAccess.SnapshotHistoryPage(
                                    List.of(second),
                                    SECOND_EVALUATED_AT,
                                    second.snapshotSha256()
                            );
                        }
                        return new DecisionInputRuntimeAccess.SnapshotHistoryPage(
                                List.of(second, first),
                                null,
                                null
                        );
                    }
                    assert beforeAt.equals(SECOND_EVALUATED_AT);
                    assert beforeSha.equals(second.snapshotSha256());
                    return new DecisionInputRuntimeAccess.SnapshotHistoryPage(
                            List.of(first),
                            null,
                            null
                    );
                },
                (limit, afterRevision) -> {
                    if (afterRevision != null && afterRevision >= policy.revision()) {
                        return new DecisionInputRuntimeAccess.MethodologyPage(List.of(), null);
                    }
                    return new DecisionInputRuntimeAccess.MethodologyPage(List.of(policy), null);
                }
        );
        return new Fixture(
                new DecisionInputApi(runtime),
                policy,
                first,
                second,
                materializations
        );
    }

    private static RbvmDecisionMethodologyPolicy policy() {
        EnumMap<EvidenceDimension, EvidenceSelectionPolicy> policies =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            policies.put(
                    dimension,
                    new EvidenceSelectionPolicy(
                            dimension,
                            ALL_SOURCES,
                            List.of(),
                            NO_AGE_LIMIT,
                            null
                    )
            );
        }
        return RbvmDecisionMethodologyPolicy.create(
                3,
                FINDING,
                PRESERVE_UNKNOWN,
                PRESERVE_AMBIGUOUS,
                EXCLUDE_LEGACY_PRIORITY_TIER,
                policies
        );
    }

    private static RbvmDecisionInputSnapshot snapshot(
            RbvmDecisionMethodologyPolicy policy,
            Instant evaluatedAt
    ) {
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
                policy.revision(),
                policy.policySha256(),
                evaluatedAt,
                dimensions
        );
    }

    private static String materializationBody(RbvmDecisionMethodologyPolicy policy) {
        return "{"
                + "\"findingId\":\"" + FINDING_ID + "\","
                + "\"methodologyRevision\":" + policy.revision() + ','
                + "\"methodologyPolicySha256\":\"" + policy.policySha256() + "\","
                + "\"evaluatedAt\":\"" + SECOND_EVALUATED_AT + "\""
                + "}";
    }

    private static ByteArrayInputStream bytes(String value) {
        return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
    }

    private static void assertProblem(ThrowingRunnable operation, int status, String code)
            throws Exception {
        boolean rejected = false;
        try {
            operation.run();
        } catch (DecisionInputApi.ApiProblem expected) {
            rejected = expected.status() == status && expected.code().equals(code);
        }
        assert rejected : "Expected " + status + '/' + code;
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private record Fixture(
            DecisionInputApi api,
            RbvmDecisionMethodologyPolicy policy,
            RbvmDecisionInputSnapshot first,
            RbvmDecisionInputSnapshot second,
            AtomicInteger materializations
    ) {
    }
}
