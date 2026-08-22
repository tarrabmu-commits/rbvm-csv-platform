package io.rbvm.csv;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmFormulaV1Explanation;
import io.rbvm.decision.RbvmResolvedDecisionInput;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.ResolvedEvidence;
import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.DecisionInputSnapshotInstallResult;
import io.rbvm.postgres.DecisionInputSnapshotStore;
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

public final class CsvFormulaResultMaterializationHttpSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("91111111-1111-4111-8111-111111111111");
    private static final UUID RESULT_ID =
            UUID.fromString("93333333-3333-4333-8333-333333333333");
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T17:00:00Z");
    private static final String POLICY_SHA = "c".repeat(64);

    private CsvFormulaResultMaterializationHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        materializesExactSnapshotThenReplaysWithoutDuplicate();
        rejectsInvalidRequestShapesAndMissingSnapshot();
        requiresOperatorBeforeDisabledCapabilityLookup();
        System.out.println("CsvFormulaResultMaterializationHttpSelfTest: PASS");
    }

    private static void materializesExactSnapshotThenReplaysWithoutDuplicate() throws Exception {
        Path data = Files.createTempDirectory("rbvm-formula-materialization-http-");
        Fixture fixture = fixture();
        MutableFormulaStore formulaStore = new MutableFormulaStore();
        FormulaResultApi api = api(fixture, formulaStore);
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data,
                ApiKeyAuthenticator.disabled(),
                Optional.of(api)
        )) {
            server.start();
            URI route = server.baseUri().resolve(
                    "/api/v1/formula-result-materializations/"
                            + fixture.snapshot().snapshotSha256()
            );

            HttpResponse<String> inserted = post(client, route, null, HttpRequest.BodyPublishers.noBody());
            assert inserted.statusCode() == 201 : inserted.body();
            assert inserted.body().contains(
                    "\"contractId\": \"RBVM_FORMULA_RESULT_MATERIALIZATION_API_V1\"");
            assert inserted.body().contains("\"materializationStatus\": \"INSERTED\"");
            assert inserted.body().contains(
                    "\"inputSnapshotSha256\": \"" + fixture.snapshot().snapshotSha256() + "\"");
            assert inserted.body().contains("\"resultState\": \"NOT_APPLICABLE\"");
            assert inserted.body().contains("\"relativeRiskIndex\": null");
            assert inserted.body().contains("\"replayVerified\": true");
            assert formulaStore.installCount == 1;
            assert formulaStore.rowCount() == 1;

            String explanationSha = formulaStore.stored().orElseThrow().explanationSha256();
            assert inserted.headers().firstValue("ETag").orElseThrow()
                    .equals(FormulaResultApi.strongEtag(explanationSha));
            String location = inserted.headers().firstValue("Location").orElseThrow();
            assert location.equals("/api/v1/formula-results/" + explanationSha);

            HttpResponse<String> exactRead = get(client, server.baseUri().resolve(location));
            assert exactRead.statusCode() == 200 : exactRead.body();
            assert exactRead.body().contains("\"contractId\": \"RBVM_FORMULA_RESULT_API_V1\"");
            assert exactRead.body().contains("\"replayVerified\": true");
            assert exactRead.body().contains(explanationSha);

            HttpResponse<String> replayed = post(client, route, null, HttpRequest.BodyPublishers.noBody());
            assert replayed.statusCode() == 200 : replayed.body();
            assert replayed.body().contains("\"materializationStatus\": \"REPLAYED\"");
            assert replayed.body().contains("\"explanationSha256\": \"" + explanationSha + "\"");
            assert formulaStore.installCount == 2;
            assert formulaStore.rowCount() == 1;
        } finally {
            deleteTree(data);
        }
    }

    private static void rejectsInvalidRequestShapesAndMissingSnapshot() throws Exception {
        Path data = Files.createTempDirectory("rbvm-formula-materialization-invalid-");
        Fixture fixture = fixture();
        MutableFormulaStore formulaStore = new MutableFormulaStore();
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data,
                ApiKeyAuthenticator.disabled(),
                Optional.of(api(fixture, formulaStore))
        )) {
            server.start();
            URI base = server.baseUri();
            String prefix = "/api/v1/formula-result-materializations/";

            HttpResponse<String> malformed = post(
                    client,
                    base.resolve(prefix + "not-a-sha"),
                    null,
                    HttpRequest.BodyPublishers.noBody()
            );
            assert malformed.statusCode() == 400 : malformed.body();
            assert malformed.body().contains("INVALID FORMULA RESULT IDENTITY");

            HttpResponse<String> missing = post(
                    client,
                    base.resolve(prefix + "f".repeat(64)),
                    null,
                    HttpRequest.BodyPublishers.noBody()
            );
            assert missing.statusCode() == 404 : missing.body();
            assert missing.body().contains("DECISION INPUT SNAPSHOT NOT FOUND");

            HttpResponse<String> queryRejected = post(
                    client,
                    base.resolve(prefix + fixture.snapshot().snapshotSha256() + "?latest=true"),
                    null,
                    HttpRequest.BodyPublishers.noBody()
            );
            assert queryRejected.statusCode() == 400 : queryRejected.body();
            assert queryRejected.body().contains("INVALID FORMULA MATERIALIZATION REQUEST");

            HttpResponse<String> bodyRejected = post(
                    client,
                    base.resolve(prefix + fixture.snapshot().snapshotSha256()),
                    null,
                    HttpRequest.BodyPublishers.ofString("{}")
            );
            assert bodyRejected.statusCode() == 400 : bodyRejected.body();
            assert bodyRejected.body().contains("FORMULA MATERIALIZATION BODY NOT ALLOWED");

            HttpResponse<String> wrongMethod = get(
                    client,
                    base.resolve(prefix + fixture.snapshot().snapshotSha256())
            );
            assert wrongMethod.statusCode() == 405 : wrongMethod.body();
            assert "POST".equals(wrongMethod.headers().firstValue("Allow").orElse(null));

            HttpResponse<String> nested = post(
                    client,
                    base.resolve(prefix + fixture.snapshot().snapshotSha256() + "/latest"),
                    null,
                    HttpRequest.BodyPublishers.noBody()
            );
            assert nested.statusCode() == 404 : nested.body();
            assert formulaStore.rowCount() == 0;
        } finally {
            deleteTree(data);
        }
    }

    private static void requiresOperatorBeforeDisabledCapabilityLookup() throws Exception {
        Path data = Files.createTempDirectory("rbvm-formula-materialization-auth-");
        String viewerToken = "formula-materialization-viewer-token-abcdefghijklmnopqrstuvwxyz";
        String operatorToken = "formula-materialization-operator-token-abcdefghijklmnopqrstuvwxyz";
        Path keyRegistry = data.resolve("api-keys.conf");
        Files.writeString(
                keyRegistry,
                digest(viewerToken) + "=formula-viewer|VIEWER\n"
                        + digest(operatorToken) + "=formula-operator|OPERATOR\n",
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
                Optional.empty()
        )) {
            server.start();
            URI route = server.baseUri().resolve(
                    "/api/v1/formula-result-materializations/" + "a".repeat(64)
            );

            HttpResponse<String> unauthenticated = post(
                    client,
                    route,
                    null,
                    HttpRequest.BodyPublishers.noBody()
            );
            assert unauthenticated.statusCode() == 401 : unauthenticated.body();
            assert !unauthenticated.body().contains("PERSISTENCE UNAVAILABLE");

            HttpResponse<String> viewer = post(
                    client,
                    route,
                    viewerToken,
                    HttpRequest.BodyPublishers.noBody()
            );
            assert viewer.statusCode() == 403 : viewer.body();
            assert viewer.body().contains("INSUFFICIENT ROLE");
            assert !viewer.body().contains("PERSISTENCE UNAVAILABLE");

            HttpResponse<String> operator = post(
                    client,
                    route,
                    operatorToken,
                    HttpRequest.BodyPublishers.noBody()
            );
            assert operator.statusCode() == 503 : operator.body();
            assert operator.body().contains("FORMULA RESULT PERSISTENCE UNAVAILABLE");
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

    private static FormulaResultApi api(Fixture fixture, MutableFormulaStore formulaStore) {
        DecisionInputSnapshotStore snapshotStore = decisionStore(fixture.snapshot());
        FormulaResultReplayVerifier verifier = new FormulaResultReplayVerifier(
                formulaStore,
                snapshotStore,
                ignored -> fixture.resolved()
        );
        return new FormulaResultApi(formulaStore, verifier);
    }

    private static Fixture fixture() {
        EvidenceReference applicability = new EvidenceReference(
                EvidenceDimension.APPLICABILITY,
                UUID.fromString("92222222-2222-4222-8222-222222222222"),
                "d".repeat(64),
                "CUSTOMER_APPLICABILITY",
                EVALUATED_AT.minusSeconds(60)
        );

        EnumMap<EvidenceDimension, DimensionInput> dimensions =
                new EnumMap<>(EvidenceDimension.class);
        EnumMap<EvidenceDimension, List<ResolvedEvidence>> values =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            dimensions.put(
                    dimension,
                    new DimensionInput(dimension, DimensionState.MISSING, List.of())
            );
            values.put(dimension, List.of());
        }
        dimensions.put(
                EvidenceDimension.APPLICABILITY,
                new DimensionInput(
                        EvidenceDimension.APPLICABILITY,
                        DimensionState.PRESENT,
                        List.of(applicability)
                )
        );
        values.put(
                EvidenceDimension.APPLICABILITY,
                List.of(new ApplicabilityEvidenceValue(
                        applicability,
                        ApplicabilityStatus.NOT_APPLICABLE,
                        "customer-confirmed not applicable"
                ))
        );

        RbvmDecisionInputSnapshot snapshot = RbvmDecisionInputSnapshot.createV3(
                FINDING_ID,
                9,
                POLICY_SHA,
                EVALUATED_AT,
                dimensions
        );
        RbvmResolvedDecisionInput resolved = new RbvmResolvedDecisionInput(snapshot, values);
        return new Fixture(snapshot, resolved);
    }

    private static DecisionInputSnapshotStore decisionStore(RbvmDecisionInputSnapshot snapshot) {
        return new DecisionInputSnapshotStore() {
            @Override
            public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot ignored) {
                throw new UnsupportedOperationException("materialization HTTP test uses persisted fixture");
            }

            @Override
            public Optional<RbvmDecisionInputSnapshot> findBySha256(String sha256) {
                return snapshot.snapshotSha256().equals(sha256)
                        ? Optional.of(snapshot)
                        : Optional.empty();
            }
        };
    }

    private static StoredFormulaResult toStored(RbvmFormulaV1Explanation explanation) {
        return new StoredFormulaResult(
                RESULT_ID,
                explanation.inputSnapshotSha256(),
                explanation.findingId(),
                explanation.evaluatedAt(),
                explanation.methodologyRevision(),
                explanation.methodologyPolicySha256(),
                explanation.formulaId(),
                explanation.formulaVersion(),
                explanation.formulaSha256(),
                explanation.resultState(),
                explanation.reasonCodes(),
                explanation.finalRiskResult(),
                RbvmFormulaV1Explanation.PAYLOAD_FORMAT,
                explanation.canonicalSha256(),
                explanation.canonicalPayload(),
                EVALUATED_AT.plusSeconds(5)
        );
    }

    private static HttpClient client() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    private static HttpResponse<String> get(HttpClient client, URI uri) throws Exception {
        return client.send(
                HttpRequest.newBuilder(uri)
                        .timeout(Duration.ofSeconds(10))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static HttpResponse<String> post(
            HttpClient client,
            URI uri,
            String token,
            HttpRequest.BodyPublisher body
    ) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10));
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        return client.send(
                request.POST(body).build(),
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
            RbvmDecisionInputSnapshot snapshot,
            RbvmResolvedDecisionInput resolved
    ) {
    }

    private static final class MutableFormulaStore implements FormulaResultStore {
        private StoredFormulaResult stored;
        private int installCount;

        @Override
        public FormulaResultInstallResult install(RbvmFormulaV1Explanation explanation) {
            installCount++;
            if (stored == null) {
                stored = toStored(explanation);
                return new FormulaResultInstallResult(
                        FormulaResultInstallResult.Status.INSERTED,
                        explanation.canonicalSha256(),
                        explanation.canonicalSha256()
                );
            }
            boolean same = stored.explanationSha256().equals(explanation.canonicalSha256())
                    && java.util.Arrays.equals(
                            stored.explanationPayload(),
                            explanation.canonicalPayload()
                    );
            return new FormulaResultInstallResult(
                    same
                            ? FormulaResultInstallResult.Status.REPLAYED
                            : FormulaResultInstallResult.Status.RESULT_CONFLICT,
                    explanation.canonicalSha256(),
                    stored.explanationSha256()
            );
        }

        @Override
        public Optional<StoredFormulaResult> findByExplanationSha256(String sha256) {
            return stored != null && stored.explanationSha256().equals(sha256)
                    ? Optional.of(stored)
                    : Optional.empty();
        }

        @Override
        public Optional<StoredFormulaResult> findBySnapshotAndFormula(
                String inputSnapshotSha256,
                String formulaSha256
        ) {
            return stored != null
                    && stored.inputSnapshotSha256().equals(inputSnapshotSha256)
                    && stored.formulaSha256().equals(formulaSha256)
                    ? Optional.of(stored)
                    : Optional.empty();
        }

        Optional<StoredFormulaResult> stored() {
            return Optional.ofNullable(stored);
        }

        int rowCount() {
            return stored == null ? 0 : 1;
        }
    }
}
