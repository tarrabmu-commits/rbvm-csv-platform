package io.rbvm.csv;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy;
import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.DecisionInputRuntimeAccess;
import io.rbvm.postgres.DecisionInputSnapshotInstallResult;
import io.rbvm.postgres.DecisionInputSnapshotMaterializationResult;
import io.rbvm.postgres.DecisionInputSnapshotStore;
import io.rbvm.postgres.DecisionMethodologyPolicyInstallResult;
import io.rbvm.postgres.DecisionMethodologyPolicyStore;
import io.rbvm.postgres.FormulaResultInstallResult;
import io.rbvm.postgres.FormulaResultReplayVerifier;
import io.rbvm.postgres.FormulaResultStore;
import io.rbvm.postgres.StoredFormulaResult;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.RequestRateLimiter;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.AmbiguityHandling.PRESERVE_AMBIGUOUS;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.FreshnessMode.NO_AGE_LIMIT;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.LegacyPriorityHandling.EXCLUDE_LEGACY_PRIORITY_TIER;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.MissingEvidenceHandling.PRESERVE_UNKNOWN;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.SourceSelectionMode.ALL_SOURCES;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.SubjectScope.FINDING;

public final class CsvDecisionInputHttpSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("b1111111-1111-4111-8111-111111111111");
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T18:00:00Z");

    private CsvDecisionInputHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesExactReadsHistoryCatalogAndExplicitMaterialization();
        rejectsHiddenSelectorsAndWrongMethods();
        requiresOperatorBeforeDecisionInputCapabilityLookup();
        System.out.println("CsvDecisionInputHttpSelfTest: PASS");
    }

    private static void exposesExactReadsHistoryCatalogAndExplicitMaterialization()
            throws Exception {
        Path data = Files.createTempDirectory("rbvm-decision-input-http-");
        Fixture fixture = fixture();
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data,
                ApiKeyAuthenticator.disabled(),
                Optional.of(formulaApi(fixture, true))
        )) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> catalog = get(
                    client,
                    base.resolve("/api/v1/decision-methodologies")
            );
            assert catalog.statusCode() == 200 : catalog.body();
            assert catalog.body().contains("RBVM_DECISION_METHODOLOGY_CATALOG_API_V1");
            assert catalog.body().contains(
                    "REVISION_ASCENDING_FOR_PAGINATION_ONLY_NO_PRECEDENCE_OR_PREFERENCE"
            );
            assert !catalog.body().contains("\"preferred\"");

            HttpResponse<String> methodology = get(
                    client,
                    base.resolve("/api/v1/decision-methodologies/" + fixture.policy().revision())
            );
            assert methodology.statusCode() == 200 : methodology.body();
            assert methodology.body().contains(fixture.policy().policySha256());
            assert methodology.headers().firstValue("ETag").isPresent();

            HttpResponse<String> history = get(
                    client,
                    base.resolve("/api/v1/findings/" + FINDING_ID
                            + "/decision-input-snapshots?limit=1")
            );
            assert history.statusCode() == 200 : history.body();
            assert history.body().contains(fixture.snapshot().snapshotSha256());
            assert !history.body().contains("\"latest\"");
            assert !history.body().contains("\"current\"");

            String requestBody = materializationBody(fixture.policy());
            HttpResponse<String> inserted = post(
                    client,
                    base.resolve("/api/v1/decision-input-materializations"),
                    null,
                    requestBody,
                    true
            );
            assert inserted.statusCode() == 201 : inserted.body();
            assert inserted.body().contains("RBVM_DECISION_INPUT_MATERIALIZATION_API_V1");
            assert inserted.body().contains("\"materializationStatus\": \"INSERTED\"");
            assert inserted.headers().firstValue("Location").orElseThrow().equals(
                    "/api/v1/decision-input-snapshots/" + fixture.snapshot().snapshotSha256()
            );

            HttpResponse<String> replay = post(
                    client,
                    base.resolve("/api/v1/decision-input-materializations"),
                    null,
                    requestBody,
                    true
            );
            assert replay.statusCode() == 200 : replay.body();
            assert replay.body().contains("\"materializationStatus\": \"REPLAYED\"");
            assert fixture.materializations().get() == 2;

            HttpResponse<String> exact = get(
                    client,
                    base.resolve("/api/v1/decision-input-snapshots/"
                            + fixture.snapshot().snapshotSha256())
            );
            assert exact.statusCode() == 200 : exact.body();
            assert exact.body().contains("RBVM_DECISION_INPUT_SNAPSHOT_V3");
            assert exact.body().contains("\"state\": \"MISSING\"");
            assert exact.headers().firstValue("ETag").orElseThrow().equals(
                    DecisionInputApi.strongEtag(fixture.snapshot().snapshotSha256())
            );
        } finally {
            deleteTree(data);
        }
    }

    private static void rejectsHiddenSelectorsAndWrongMethods() throws Exception {
        Path data = Files.createTempDirectory("rbvm-decision-input-invalid-");
        Fixture fixture = fixture();
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data,
                ApiKeyAuthenticator.disabled(),
                Optional.of(formulaApi(fixture, true))
        )) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> hidden = get(
                    client,
                    base.resolve("/api/v1/decision-methodologies?latest=true")
            );
            assert hidden.statusCode() == 400 : hidden.body();

            HttpResponse<String> incompleteCursor = get(
                    client,
                    base.resolve("/api/v1/findings/" + FINDING_ID
                            + "/decision-input-snapshots?beforeEvaluatedAt="
                            + EVALUATED_AT.toString().replace(":", "%3A"))
            );
            assert incompleteCursor.statusCode() == 400 : incompleteCursor.body();
            assert incompleteCursor.body().contains("BEFORE EVALUATED AT AND BEFORE SNAPSHOT SHA256");

            HttpResponse<String> queryOnExact = get(
                    client,
                    base.resolve("/api/v1/decision-input-snapshots/"
                            + fixture.snapshot().snapshotSha256() + "?current=true")
            );
            assert queryOnExact.statusCode() == 400 : queryOnExact.body();

            HttpResponse<String> wrongMethod = post(
                    client,
                    base.resolve("/api/v1/decision-methodologies"),
                    null,
                    "{}",
                    true
            );
            assert wrongMethod.statusCode() == 405 : wrongMethod.body();
            assert "GET".equals(wrongMethod.headers().firstValue("Allow").orElse(null));

            HttpResponse<String> unknownBody = post(
                    client,
                    base.resolve("/api/v1/decision-input-materializations"),
                    null,
                    materializationBody(fixture.policy()).replace("}", ",\"latest\":true}"),
                    true
            );
            assert unknownBody.statusCode() == 400 : unknownBody.body();
            assert unknownBody.body().contains("UNKNOWN DECISION INPUT MATERIALIZATION FIELDS");
        } finally {
            deleteTree(data);
        }
    }

    private static void requiresOperatorBeforeDecisionInputCapabilityLookup() throws Exception {
        Path data = Files.createTempDirectory("rbvm-decision-input-auth-");
        String viewerToken = "decision-input-viewer-token-abcdefghijklmnopqrstuvwxyz";
        String operatorToken = "decision-input-operator-token-abcdefghijklmnopqrstuvwxyz";
        Path keyRegistry = data.resolve("api-keys.conf");
        Files.writeString(
                keyRegistry,
                digest(viewerToken) + "=decision-viewer|VIEWER\n"
                        + digest(operatorToken) + "=decision-operator|OPERATOR\n",
                StandardCharsets.UTF_8
        );
        try {
            Files.setPosixFilePermissions(keyRegistry, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystems rely on platform ACLs.
        }

        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data.resolve("evidence"),
                ApiKeyAuthenticator.fromFile(keyRegistry),
                Optional.of(formulaApi(fixture(), false))
        )) {
            server.start();
            URI route = server.baseUri().resolve("/api/v1/decision-input-materializations");

            HttpResponse<String> unauthenticated = post(
                    client,
                    route,
                    null,
                    "{}",
                    true
            );
            assert unauthenticated.statusCode() == 401 : unauthenticated.body();
            assert !unauthenticated.body().contains("RUNTIME UNAVAILABLE");

            HttpResponse<String> viewer = post(
                    client,
                    route,
                    viewerToken,
                    "{}",
                    true
            );
            assert viewer.statusCode() == 403 : viewer.body();
            assert viewer.body().contains("INSUFFICIENT ROLE");
            assert !viewer.body().contains("RUNTIME UNAVAILABLE");

            HttpResponse<String> operator = post(
                    client,
                    route,
                    operatorToken,
                    "{}",
                    true
            );
            assert operator.statusCode() == 503 : operator.body();
            assert operator.body().contains("DECISION INPUT RUNTIME UNAVAILABLE");
        } finally {
            deleteTree(data);
        }
    }

    private static CsvPlatformServer server(
            Path data,
            ApiKeyAuthenticator authenticator,
            Optional<FormulaResultApi> formulaApi
    ) throws Exception {
        CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1",
                0,
                data,
                1024 * 1024,
                new NoopCanonicalProjection(),
                new InMemoryDomainCatalog(),
                authenticator,
                RequestRateLimiter.disabled()
        );
        formulaApi.ifPresent(server::enableFormulaResultApi);
        return server;
    }

    private static FormulaResultApi formulaApi(Fixture fixture, boolean includeDecisionInput) {
        FormulaResultStore formulaStore = emptyFormulaStore();
        DecisionInputSnapshotStore snapshotStore = fixture.snapshotStore();
        FormulaResultReplayVerifier verifier = includeDecisionInput
                ? new FormulaResultReplayVerifier(
                        formulaStore,
                        snapshotStore,
                        ignored -> { throw new java.io.IOException("Formula replay not used"); },
                        fixture.runtime()
                )
                : new FormulaResultReplayVerifier(
                        formulaStore,
                        snapshotStore,
                        ignored -> { throw new java.io.IOException("Formula replay not used"); }
                );
        return new FormulaResultApi(formulaStore, verifier);
    }

    private static FormulaResultStore emptyFormulaStore() {
        return new FormulaResultStore() {
            @Override
            public FormulaResultInstallResult install(
                    io.rbvm.decision.RbvmFormulaV1Explanation ignored
            ) {
                throw new UnsupportedOperationException("Formula write not used");
            }

            @Override
            public Optional<StoredFormulaResult> findByExplanationSha256(String ignored) {
                return Optional.empty();
            }

            @Override
            public Optional<StoredFormulaResult> findBySnapshotAndFormula(
                    String ignoredSnapshot,
                    String ignoredFormula
            ) {
                return Optional.empty();
            }
        };
    }

    private static Fixture fixture() {
        RbvmDecisionMethodologyPolicy policy = policy();
        RbvmDecisionInputSnapshot snapshot = snapshot(policy);
        AtomicInteger materializations = new AtomicInteger();

        DecisionMethodologyPolicyStore methodologyStore = new DecisionMethodologyPolicyStore() {
            @Override
            public DecisionMethodologyPolicyInstallResult install(
                    RbvmDecisionMethodologyPolicy ignored
            ) {
                throw new UnsupportedOperationException("not used");
            }

            @Override
            public Optional<RbvmDecisionMethodologyPolicy> findByRevision(int revision) {
                return revision == policy.revision() ? Optional.of(policy) : Optional.empty();
            }
        };
        DecisionInputSnapshotStore snapshotStore = new DecisionInputSnapshotStore() {
            @Override
            public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot ignored) {
                throw new UnsupportedOperationException("not used");
            }

            @Override
            public Optional<RbvmDecisionInputSnapshot> findBySha256(String sha) {
                return snapshot.snapshotSha256().equals(sha)
                        ? Optional.of(snapshot)
                        : Optional.empty();
            }
        };
        DecisionInputRuntimeAccess runtime = new DecisionInputRuntimeAccess(
                methodologyStore,
                snapshotStore,
                (findingId, revision, policySha, evaluatedAt) -> {
                    assert findingId.equals(FINDING_ID);
                    assert revision == policy.revision();
                    assert policySha.equals(policy.policySha256());
                    assert evaluatedAt.equals(EVALUATED_AT);
                    DecisionInputSnapshotInstallResult.Status status =
                            materializations.getAndIncrement() == 0
                                    ? DecisionInputSnapshotInstallResult.Status.INSERTED
                                    : DecisionInputSnapshotInstallResult.Status.REPLAYED;
                    return new DecisionInputSnapshotMaterializationResult(
                            snapshot,
                            new DecisionInputSnapshotInstallResult(
                                    status,
                                    snapshot.snapshotSha256(),
                                    snapshot.snapshotSha256()
                            )
                    );
                },
                (findingId, limit, beforeAt, beforeSha) -> {
                    assert findingId.equals(FINDING_ID);
                    return new DecisionInputRuntimeAccess.SnapshotHistoryPage(
                            List.of(snapshot),
                            null,
                            null
                    );
                },
                (limit, afterRevision) -> new DecisionInputRuntimeAccess.MethodologyPage(
                        afterRevision == null || afterRevision < policy.revision()
                                ? List.of(policy)
                                : List.of(),
                        null
                )
        );
        return new Fixture(policy, snapshot, snapshotStore, runtime, materializations);
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
                5,
                FINDING,
                PRESERVE_UNKNOWN,
                PRESERVE_AMBIGUOUS,
                EXCLUDE_LEGACY_PRIORITY_TIER,
                policies
        );
    }

    private static RbvmDecisionInputSnapshot snapshot(RbvmDecisionMethodologyPolicy policy) {
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
                EVALUATED_AT,
                dimensions
        );
    }

    private static String materializationBody(RbvmDecisionMethodologyPolicy policy) {
        return "{"
                + "\"findingId\":\"" + FINDING_ID + "\","
                + "\"methodologyRevision\":" + policy.revision() + ','
                + "\"methodologyPolicySha256\":\"" + policy.policySha256() + "\","
                + "\"evaluatedAt\":\"" + EVALUATED_AT + "\""
                + "}";
    }

    private static HttpClient client() {
        return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    }

    private static HttpResponse<String> get(HttpClient client, URI uri) throws Exception {
        return client.send(
                HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10)).GET().build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static HttpResponse<String> post(
            HttpClient client,
            URI uri,
            String token,
            String body,
            boolean json
    ) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10));
        if (token != null) request.header("Authorization", "Bearer " + token);
        if (json) request.header("Content-Type", "application/json");
        return client.send(
                request.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static String digest(String value) throws Exception {
        return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256")
                        .digest(value.getBytes(StandardCharsets.UTF_8))
        );
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var stream = Files.walk(root)) {
            for (Path path : stream.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private record Fixture(
            RbvmDecisionMethodologyPolicy policy,
            RbvmDecisionInputSnapshot snapshot,
            DecisionInputSnapshotStore snapshotStore,
            DecisionInputRuntimeAccess runtime,
            AtomicInteger materializations
    ) {
    }
}
