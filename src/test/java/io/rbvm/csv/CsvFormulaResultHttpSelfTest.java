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

public final class CsvFormulaResultHttpSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("81111111-1111-4111-8111-111111111111");
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T16:00:00Z");
    private static final String POLICY_SHA = "a".repeat(64);

    private CsvFormulaResultHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesExactReplayVerifiedReadsOnly();
        reportsDisabledCapabilityWithoutV23();
        protectsDisabledCapabilityBehindViewerAuthentication();
        System.out.println("CsvFormulaResultHttpSelfTest: PASS");
    }

    private static void exposesExactReplayVerifiedReadsOnly() throws Exception {
        Path data = Files.createTempDirectory("rbvm-formula-result-http-");
        Fixture fixture = fixture();
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data,
                ApiKeyAuthenticator.disabled(),
                Optional.of(api(fixture))
        )) {
            server.start();
            URI base = server.baseUri();
            String explanationSha = fixture.explanation().canonicalSha256();

            HttpResponse<String> byExplanation = get(
                    client,
                    base.resolve("/api/v1/formula-results/" + explanationSha)
            );
            assert byExplanation.statusCode() == 200 : byExplanation.body();
            assert byExplanation.headers().firstValue("ETag").orElseThrow()
                    .equals(FormulaResultApi.strongEtag(explanationSha));
            assert byExplanation.body().contains("\"contractId\": \"RBVM_FORMULA_RESULT_API_V1\"");
            assert byExplanation.body().contains("\"resultState\": \"NOT_APPLICABLE\"");
            assert byExplanation.body().contains("\"relativeRiskIndex\": null");
            assert byExplanation.body().contains("\"replayVerified\": true");
            assert byExplanation.body().contains("\"sha256\": \"" + explanationSha + "\"");

            URI exactPair = base.resolve(
                    "/api/v1/formula-results?inputSnapshotSha256="
                            + fixture.snapshot().snapshotSha256()
                            + "&formulaSha256=" + RbvmFormulaV1.FORMULA_SHA256
            );
            HttpResponse<String> byPair = get(client, exactPair);
            assert byPair.statusCode() == 200 : byPair.body();
            assert byPair.body().contains(fixture.stored().id().toString());
            assert byPair.body().contains(fixture.snapshot().snapshotSha256());

            HttpResponse<String> invalidSha = get(
                    client,
                    base.resolve("/api/v1/formula-results/not-a-sha")
            );
            assert invalidSha.statusCode() == 400 : invalidSha.body();
            assert invalidSha.body().contains("INVALID FORMULA RESULT IDENTITY");

            HttpResponse<String> missing = get(
                    client,
                    base.resolve("/api/v1/formula-results/" + "f".repeat(64))
            );
            assert missing.statusCode() == 404 : missing.body();
            assert missing.body().contains("FORMULA RESULT NOT FOUND");

            HttpResponse<String> missingQueryField = get(
                    client,
                    base.resolve("/api/v1/formula-results?inputSnapshotSha256="
                            + fixture.snapshot().snapshotSha256())
            );
            assert missingQueryField.statusCode() == 400 : missingQueryField.body();
            assert missingQueryField.body().contains("INVALID FORMULA RESULT QUERY");

            HttpResponse<String> unknownQueryField = get(
                    client,
                    base.resolve("/api/v1/formula-results?inputSnapshotSha256="
                            + fixture.snapshot().snapshotSha256()
                            + "&formulaSha256=" + RbvmFormulaV1.FORMULA_SHA256
                            + "&latest=true")
            );
            assert unknownQueryField.statusCode() == 400 : unknownQueryField.body();
            assert unknownQueryField.body().contains("INVALID FORMULA RESULT QUERY");

            HttpResponse<String> duplicateQueryField = get(
                    client,
                    base.resolve("/api/v1/formula-results?inputSnapshotSha256="
                            + fixture.snapshot().snapshotSha256()
                            + "&inputSnapshotSha256=" + fixture.snapshot().snapshotSha256()
                            + "&formulaSha256=" + RbvmFormulaV1.FORMULA_SHA256)
            );
            assert duplicateQueryField.statusCode() == 400 : duplicateQueryField.body();

            HttpResponse<String> itemQueryRejected = get(
                    client,
                    base.resolve("/api/v1/formula-results/" + explanationSha + "?latest=true")
            );
            assert itemQueryRejected.statusCode() == 400 : itemQueryRejected.body();

            HttpRequest post = HttpRequest.newBuilder(
                            base.resolve("/api/v1/formula-results/" + explanationSha))
                    .timeout(Duration.ofSeconds(10))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<String> writeRejected = client.send(
                    post,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert writeRejected.statusCode() == 405 : writeRejected.body();
            assert "GET".equals(writeRejected.headers().firstValue("Allow").orElse(null));

            HttpResponse<String> nestedUnknown = get(
                    client,
                    base.resolve("/api/v1/formula-results/a/b")
            );
            assert nestedUnknown.statusCode() == 404 : nestedUnknown.body();

            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"formulaResults\"");
            assert health.body().contains("\"readEnabled\": true");
            assert health.body().contains("\"replayVerified\": true");

            HttpResponse<String> metrics = get(client, base.resolve("/api/v1/metrics"));
            assert metrics.statusCode() == 200 : metrics.body();
            assert metrics.body().contains("rbvm_formula_result_api_enabled 1");
        } finally {
            deleteTree(data);
        }
    }

    private static void reportsDisabledCapabilityWithoutV23() throws Exception {
        Path data = Files.createTempDirectory("rbvm-formula-result-disabled-");
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1",
                0,
                data,
                1024 * 1024
        )) {
            server.start();
            URI base = server.baseUri();
            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"formulaResults\"");
            assert health.body().contains("\"readEnabled\": false");

            HttpResponse<String> unavailable = get(
                    client,
                    base.resolve("/api/v1/formula-results?inputSnapshotSha256="
                            + "a".repeat(64) + "&formulaSha256=" + "b".repeat(64))
            );
            assert unavailable.statusCode() == 503 : unavailable.body();
            assert unavailable.body().contains("FORMULA RESULT PERSISTENCE UNAVAILABLE");

            HttpResponse<String> metrics = get(client, base.resolve("/api/v1/metrics"));
            assert metrics.body().contains("rbvm_formula_result_api_enabled 0");
        } finally {
            deleteTree(data);
        }
    }

    private static void protectsDisabledCapabilityBehindViewerAuthentication() throws Exception {
        Path data = Files.createTempDirectory("rbvm-formula-result-auth-");
        String viewerToken = "formula-viewer-token-abcdefghijklmnopqrstuvwxyz-123";
        Path keyRegistry = data.resolve("api-keys.conf");
        Files.writeString(
                keyRegistry,
                digest(viewerToken) + "=formula-viewer|VIEWER\n",
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
                    "/api/v1/formula-results?inputSnapshotSha256="
                            + "a".repeat(64) + "&formulaSha256=" + "b".repeat(64)
            );

            HttpResponse<String> unauthenticated = get(client, route);
            assert unauthenticated.statusCode() == 401 : unauthenticated.body();
            assert !unauthenticated.body().contains("PERSISTENCE UNAVAILABLE");

            HttpResponse<String> viewer = authorizedGet(client, route, viewerToken);
            assert viewer.statusCode() == 503 : viewer.body();
            assert viewer.body().contains("FORMULA RESULT PERSISTENCE UNAVAILABLE");
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

    private static FormulaResultApi api(Fixture fixture) {
        FormulaResultStore formulaStore = formulaStore(fixture.stored());
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
                UUID.fromString("82222222-2222-4222-8222-222222222222"),
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
        RbvmFormulaV1.FormulaResult result = RbvmFormulaV1.evaluate(resolved);
        RbvmFormulaV1Explanation explanation = RbvmFormulaV1Explanation.from(resolved, result);
        StoredFormulaResult stored = new StoredFormulaResult(
                UUID.fromString("83333333-3333-4333-8333-333333333333"),
                snapshot.snapshotSha256(),
                snapshot.findingId(),
                snapshot.evaluatedAt(),
                snapshot.methodologyRevision(),
                snapshot.methodologyPolicySha256(),
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
        return new Fixture(snapshot, resolved, explanation, stored);
    }

    private static FormulaResultStore formulaStore(StoredFormulaResult stored) {
        return new FormulaResultStore() {
            @Override
            public FormulaResultInstallResult install(RbvmFormulaV1Explanation explanation) {
                throw new UnsupportedOperationException("read-only HTTP test store");
            }

            @Override
            public Optional<StoredFormulaResult> findByExplanationSha256(String sha256) {
                return stored.explanationSha256().equals(sha256)
                        ? Optional.of(stored)
                        : Optional.empty();
            }

            @Override
            public Optional<StoredFormulaResult> findBySnapshotAndFormula(
                    String inputSnapshotSha256,
                    String formulaSha256
            ) {
                return stored.inputSnapshotSha256().equals(inputSnapshotSha256)
                        && stored.formulaSha256().equals(formulaSha256)
                        ? Optional.of(stored)
                        : Optional.empty();
            }
        };
    }

    private static DecisionInputSnapshotStore decisionStore(RbvmDecisionInputSnapshot snapshot) {
        return new DecisionInputSnapshotStore() {
            @Override
            public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot ignored) {
                throw new UnsupportedOperationException("read-only HTTP test store");
            }

            @Override
            public Optional<RbvmDecisionInputSnapshot> findBySha256(String sha256) {
                return snapshot.snapshotSha256().equals(sha256)
                        ? Optional.of(snapshot)
                        : Optional.empty();
            }
        };
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
            RbvmResolvedDecisionInput resolved,
            RbvmFormulaV1Explanation explanation,
            StoredFormulaResult stored
    ) {
    }
}
