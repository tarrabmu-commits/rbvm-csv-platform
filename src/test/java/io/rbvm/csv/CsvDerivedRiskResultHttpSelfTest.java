package io.rbvm.csv;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDerivedRiskCanonicalResult;
import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.decision.RbvmResolvedDecisionInput;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.ResolvedEvidence;
import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.DecisionInputSnapshotInstallResult;
import io.rbvm.postgres.DecisionInputSnapshotStore;
import io.rbvm.postgres.DefaultDerivedRiskResultMaterializer;
import io.rbvm.postgres.DerivedRiskResultInstallResult;
import io.rbvm.postgres.DerivedRiskResultReplayVerifier;
import io.rbvm.postgres.DerivedRiskResultStore;
import io.rbvm.postgres.StoredDerivedRiskResult;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** End-to-end dependency-free HTTP proof for explicit V24 derived-risk transport. */
public final class CsvDerivedRiskResultHttpSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("a1111111-1111-4111-8111-111111111111");
    private static final String POLICY_SHA = "a".repeat(64);
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T20:00:00Z");

    private CsvDerivedRiskResultHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesCatalogExactReadsAndExplicitMaterialization();
        rejectsInvalidRequestShapesAndAliases();
        protectsDisabledCapabilityBehindViewerAndOperatorAuthorization();
        System.out.println("CsvDerivedRiskResultHttpSelfTest: PASS");
    }

    private static void exposesCatalogExactReadsAndExplicitMaterialization() throws Exception {
        Path data = Files.createTempDirectory("rbvm-derived-risk-http-");
        Fixture fixture = fixture();
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data,
                ApiKeyAuthenticator.disabled(),
                Optional.of(fixture.api())
        )) {
            server.start();

            HttpResponse<String> catalog = get(
                    client,
                    server.baseUri().resolve("/api/v1/derived-risk-methodologies")
            );
            assert catalog.statusCode() == 200 : catalog.body();
            assert catalog.body().contains("RBVM_DERIVED_RISK_METHODOLOGY_CATALOG_API_V1");
            assert catalog.body().contains("EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT");
            assert catalog.body().contains("OWASP_DERIVED_RBVM_V1");
            assert catalog.body().contains("MICROSOFT_PD_DERIVED_RBVM_V1");
            assert !catalog.body().contains("preferredMethodology");
            assert !catalog.body().contains("defaultMethodology");

            for (RbvmDerivedRiskMethodology.Definition definition
                    : RbvmDerivedRiskMethodologyCatalog.definitions()) {
                URI materialize = server.baseUri().resolve(
                        "/api/v1/derived-risk-result-materializations/"
                                + fixture.snapshot().snapshotSha256() + "/"
                                + definition.methodologyId() + "/"
                                + definition.methodologySha256()
                );
                HttpResponse<String> inserted = post(client, materialize);
                assert inserted.statusCode() == 201 : inserted.body();
                assert inserted.body().contains("RBVM_DERIVED_RISK_RESULT_MATERIALIZATION_API_V1");
                assert inserted.body().contains("\"materializationStatus\": \"INSERTED\"");
                assert inserted.body().contains("\"methodologyId\": \""
                        + definition.methodologyId() + "\"");
                assert inserted.body().contains("\"resultState\": \"NOT_APPLICABLE\"");
                assert inserted.body().contains("\"numericScore\": null");
                assert inserted.body().contains("\"replayVerified\": true");
                assert inserted.headers().firstValue("Location")
                        .orElseThrow().startsWith("/api/v1/derived-risk-results/");
                String etag = inserted.headers().firstValue("ETag").orElseThrow();
                assert etag.startsWith("\"derived-risk-result-");

                HttpResponse<String> replayed = post(client, materialize);
                assert replayed.statusCode() == 200 : replayed.body();
                assert replayed.body().contains("\"materializationStatus\": \"REPLAYED\"");

                StoredDerivedRiskResult stored = fixture.store()
                        .findBySnapshotAndMethodology(
                                fixture.snapshot().snapshotSha256(),
                                definition.methodologyId(),
                                definition.methodologySha256()
                        ).orElseThrow();

                HttpResponse<String> bySha = get(
                        client,
                        server.baseUri().resolve(
                                "/api/v1/derived-risk-results/" + stored.resultSha256()
                        )
                );
                assert bySha.statusCode() == 200 : bySha.body();
                assert bySha.body().contains("RBVM_DERIVED_RISK_RESULT_API_V1");
                assert bySha.body().contains("\"resultSha256\": \""
                        + stored.resultSha256() + "\"");
                assert bySha.body().contains("\"replayVerified\": true");
                assert bySha.body().contains("canonicalPayloadBase64");

                URI exact = URI.create(
                        server.baseUri().toString()
                                + "api/v1/derived-risk-results?inputSnapshotSha256="
                                + fixture.snapshot().snapshotSha256()
                                + "&methodologyId=" + definition.methodologyId()
                                + "&methodologySha256=" + definition.methodologySha256()
                );
                HttpResponse<String> byTuple = get(client, exact);
                assert byTuple.statusCode() == 200 : byTuple.body();
                assert byTuple.body().contains(stored.resultSha256());
            }

            assert fixture.store().size() == 2 : "exact retries must not create duplicate rows";

            HttpResponse<String> health = get(client, server.baseUri().resolve("/api/v1/health"));
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"derivedRiskResults\"");
            assert health.body().contains("\"materializationEnabled\": true");

            HttpResponse<String> metrics = get(client, server.baseUri().resolve("/api/v1/metrics"));
            assert metrics.statusCode() == 200 : metrics.body();
            assert metrics.body().contains("rbvm_derived_risk_result_api_enabled 1");
        } finally {
            deleteTree(data);
        }
    }

    private static void rejectsInvalidRequestShapesAndAliases() throws Exception {
        Path data = Files.createTempDirectory("rbvm-derived-risk-http-invalid-");
        Fixture fixture = fixture();
        HttpClient client = client();
        RbvmDerivedRiskMethodology.Definition definition =
                RbvmDerivedRiskMethodologyCatalog.definitions().get(0);
        try (CsvPlatformServer server = server(
                data,
                ApiKeyAuthenticator.disabled(),
                Optional.of(fixture.api())
        )) {
            server.start();

            HttpResponse<String> badSha = get(
                    client,
                    server.baseUri().resolve("/api/v1/derived-risk-results/ABC")
            );
            assert badSha.statusCode() == 400 : badSha.body();

            HttpResponse<String> missingQuery = get(
                    client,
                    URI.create(server.baseUri().toString()
                            + "api/v1/derived-risk-results?inputSnapshotSha256="
                            + fixture.snapshot().snapshotSha256())
            );
            assert missingQuery.statusCode() == 400 : missingQuery.body();

            HttpResponse<String> duplicate = get(
                    client,
                    URI.create(server.baseUri().toString()
                            + "api/v1/derived-risk-results?inputSnapshotSha256="
                            + fixture.snapshot().snapshotSha256()
                            + "&methodologyId=" + definition.methodologyId()
                            + "&methodologyId=" + definition.methodologyId()
                            + "&methodologySha256=" + definition.methodologySha256())
            );
            assert duplicate.statusCode() == 400 : duplicate.body();

            HttpResponse<String> latestRejected = get(
                    client,
                    URI.create(server.baseUri().toString()
                            + "api/v1/derived-risk-results?inputSnapshotSha256="
                            + fixture.snapshot().snapshotSha256()
                            + "&methodologyId=" + definition.methodologyId()
                            + "&methodologySha256=" + definition.methodologySha256()
                            + "&latest=true")
            );
            assert latestRejected.statusCode() == 400 : latestRejected.body();

            URI alias = server.baseUri().resolve(
                    "/api/v1/derived-risk-result-materializations/"
                            + fixture.snapshot().snapshotSha256() + "/"
                            + definition.methodologyId().toLowerCase() + "/"
                            + definition.methodologySha256()
            );
            HttpResponse<String> aliasRejected = post(client, alias);
            assert aliasRejected.statusCode() == 404 : aliasRejected.body();
            assert aliasRejected.body().contains("DERIVED RISK METHODOLOGY NOT FOUND");

            URI materialize = server.baseUri().resolve(
                    "/api/v1/derived-risk-result-materializations/"
                            + fixture.snapshot().snapshotSha256() + "/"
                            + definition.methodologyId() + "/"
                            + definition.methodologySha256()
            );
            HttpResponse<String> queryRejected = post(
                    client,
                    URI.create(materialize.toString() + "?latest=true")
            );
            assert queryRejected.statusCode() == 400 : queryRejected.body();

            HttpResponse<String> bodyRejected = client.send(
                    HttpRequest.newBuilder(materialize)
                            .timeout(Duration.ofSeconds(10))
                            .POST(HttpRequest.BodyPublishers.ofString("{}"))
                            .build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert bodyRejected.statusCode() == 400 : bodyRejected.body();
            assert bodyRejected.body().contains("DERIVED RISK MATERIALIZATION BODY NOT ALLOWED");

            HttpResponse<String> wrongMethod = get(client, materialize);
            assert wrongMethod.statusCode() == 405 : wrongMethod.body();
            assert wrongMethod.headers().firstValue("Allow").orElseThrow().equals("POST");

            HttpResponse<String> nested = get(
                    client,
                    server.baseUri().resolve("/api/v1/derived-risk-results/a/b")
            );
            assert nested.statusCode() == 404 : nested.body();
        } finally {
            deleteTree(data);
        }
    }

    private static void protectsDisabledCapabilityBehindViewerAndOperatorAuthorization()
            throws Exception {
        Path data = Files.createTempDirectory("rbvm-derived-risk-http-auth-");
        String viewerToken = "derived-viewer-token-abcdefghijklmnopqrstuvwxyz-123";
        String operatorToken = "derived-operator-token-abcdefghijklmnopqrstuvwxyz-123";
        Path keyRegistry = data.resolve("api-keys.conf");
        Files.writeString(
                keyRegistry,
                digest(viewerToken) + "=derived-viewer|VIEWER\n"
                        + digest(operatorToken) + "=derived-operator|OPERATOR\n",
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

        RbvmDerivedRiskMethodology.Definition definition =
                RbvmDerivedRiskMethodologyCatalog.definitions().get(0);
        String snapshotSha = "a".repeat(64);
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data.resolve("evidence"),
                ApiKeyAuthenticator.fromFile(keyRegistry),
                Optional.empty()
        )) {
            server.start();
            URI read = server.baseUri().resolve("/api/v1/derived-risk-methodologies");
            URI write = server.baseUri().resolve(
                    "/api/v1/derived-risk-result-materializations/"
                            + snapshotSha + "/"
                            + definition.methodologyId() + "/"
                            + definition.methodologySha256()
            );

            HttpResponse<String> unauthenticatedRead = get(client, read);
            assert unauthenticatedRead.statusCode() == 401 : unauthenticatedRead.body();
            assert !unauthenticatedRead.body().contains("PERSISTENCE UNAVAILABLE");

            HttpResponse<String> viewerRead = authorizedGet(client, read, viewerToken);
            assert viewerRead.statusCode() == 503 : viewerRead.body();
            assert viewerRead.body().contains("DERIVED RISK RESULT PERSISTENCE UNAVAILABLE");

            HttpResponse<String> unauthenticatedWrite = post(client, write);
            assert unauthenticatedWrite.statusCode() == 401 : unauthenticatedWrite.body();

            HttpResponse<String> viewerWrite = authorizedPost(client, write, viewerToken);
            assert viewerWrite.statusCode() == 403 : viewerWrite.body();
            assert !viewerWrite.body().contains("PERSISTENCE UNAVAILABLE");

            HttpResponse<String> operatorWrite = authorizedPost(client, write, operatorToken);
            assert operatorWrite.statusCode() == 503 : operatorWrite.body();
            assert operatorWrite.body().contains("DERIVED RISK RESULT PERSISTENCE UNAVAILABLE");

            HttpResponse<String> metrics = authorizedGet(
                    client,
                    server.baseUri().resolve("/api/v1/metrics"),
                    viewerToken
            );
            assert metrics.statusCode() == 200 : metrics.body();
            assert metrics.body().contains("rbvm_derived_risk_result_api_enabled 0");
        } finally {
            deleteTree(data);
        }
    }

    private static CsvPlatformServer server(
            Path data,
            ApiKeyAuthenticator authenticator,
            Optional<DerivedRiskResultApi> api
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
        api.ifPresent(server::enableDerivedRiskResultApi);
        return server;
    }

    private static Fixture fixture() {
        EvidenceReference applicability = new EvidenceReference(
                EvidenceDimension.APPLICABILITY,
                UUID.fromString("a2222222-2222-4222-8222-222222222222"),
                "b".repeat(64),
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
                8,
                POLICY_SHA,
                EVALUATED_AT,
                dimensions
        );
        RbvmResolvedDecisionInput resolved = new RbvmResolvedDecisionInput(snapshot, values);
        MutableDerivedRiskStore store = new MutableDerivedRiskStore();
        DecisionInputSnapshotStore snapshots = decisionStore(snapshot);
        DerivedRiskResultReplayVerifier verifier = new DerivedRiskResultReplayVerifier(
                store,
                snapshots,
                ignored -> resolved
        );
        DefaultDerivedRiskResultMaterializer materializer =
                new DefaultDerivedRiskResultMaterializer(
                        snapshots,
                        ignored -> resolved,
                        store,
                        verifier
                );
        DerivedRiskResultApi api = new DerivedRiskResultApi(store, verifier, materializer);
        return new Fixture(snapshot, resolved, store, api);
    }

    private static DecisionInputSnapshotStore decisionStore(RbvmDecisionInputSnapshot snapshot) {
        return new DecisionInputSnapshotStore() {
            @Override
            public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot ignored) {
                throw new UnsupportedOperationException("read-only HTTP test snapshot store");
            }

            @Override
            public Optional<RbvmDecisionInputSnapshot> findBySha256(String sha256) {
                return snapshot.snapshotSha256().equals(sha256)
                        ? Optional.of(snapshot)
                        : Optional.empty();
            }
        };
    }

    private static final class MutableDerivedRiskStore implements DerivedRiskResultStore {
        private final Map<String, StoredDerivedRiskResult> bySha = new LinkedHashMap<>();
        private final Map<String, StoredDerivedRiskResult> byTuple = new LinkedHashMap<>();

        @Override
        public DerivedRiskResultInstallResult install(RbvmDerivedRiskCanonicalResult result) {
            RbvmDerivedRiskMethodology.Evaluation evaluation = result.evaluation();
            RbvmDerivedRiskMethodology.Definition definition = evaluation.definition();
            String key = tuple(
                    evaluation.inputSnapshotSha256(),
                    definition.methodologyId(),
                    definition.methodologySha256()
            );
            StoredDerivedRiskResult existing = byTuple.get(key);
            if (existing != null) {
                DerivedRiskResultInstallResult.Status status = existing.resultSha256()
                        .equals(result.canonicalSha256())
                        ? DerivedRiskResultInstallResult.Status.REPLAYED
                        : DerivedRiskResultInstallResult.Status.RESULT_CONFLICT;
                return new DerivedRiskResultInstallResult(
                        status,
                        result.canonicalSha256(),
                        existing.resultSha256()
                );
            }

            StoredDerivedRiskResult stored = new StoredDerivedRiskResult(
                    new UUID(0L, bySha.size() + 1L),
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
                    result.canonicalSha256(),
                    result.canonicalPayload(),
                    EVALUATED_AT.plusSeconds(5 + bySha.size())
            );
            bySha.put(stored.resultSha256(), stored);
            byTuple.put(key, stored);
            return new DerivedRiskResultInstallResult(
                    DerivedRiskResultInstallResult.Status.INSERTED,
                    result.canonicalSha256(),
                    result.canonicalSha256()
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
            return Optional.ofNullable(byTuple.get(tuple(
                    inputSnapshotSha256,
                    methodologyId,
                    methodologySha256
            )));
        }

        int size() {
            return bySha.size();
        }

        private static String tuple(String snapshot, String methodologyId, String methodologySha) {
            return snapshot + '|' + methodologyId + '|' + methodologySha;
        }
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

    private static HttpResponse<String> post(HttpClient client, URI uri) throws Exception {
        return client.send(
                HttpRequest.newBuilder(uri)
                        .timeout(Duration.ofSeconds(10))
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static HttpResponse<String> authorizedGet(
            HttpClient client,
            URI uri,
            String token
    ) throws Exception {
        return client.send(
                HttpRequest.newBuilder(uri)
                        .timeout(Duration.ofSeconds(10))
                        .header("Authorization", "Bearer " + token)
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static HttpResponse<String> authorizedPost(
            HttpClient client,
            URI uri,
            String token
    ) throws Exception {
        return client.send(
                HttpRequest.newBuilder(uri)
                        .timeout(Duration.ofSeconds(10))
                        .header("Authorization", "Bearer " + token)
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .build(),
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
            stream.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception exception) {
                    throw new RuntimeException(exception);
                }
            });
        }
    }

    private record Fixture(
            RbvmDecisionInputSnapshot snapshot,
            RbvmResolvedDecisionInput resolved,
            MutableDerivedRiskStore store,
            DerivedRiskResultApi api
    ) {
    }
}
