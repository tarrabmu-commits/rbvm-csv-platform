package io.rbvm.csv;

import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.RiskMethodSelectionPolicyInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyStore;
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
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** End-to-end dependency-free HTTP proof for exact V25 risk-method policy transport. */
public final class CsvRiskMethodSelectionPolicyHttpSelfTest {
    private CsvRiskMethodSelectionPolicyHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        installsAndReadsExactPoliciesWithoutCurrentSemantics();
        rejectsAliasesQueriesBodiesAndWrongMethods();
        protectsDisabledCapabilityBehindAuthorization();
        System.out.println("CsvRiskMethodSelectionPolicyHttpSelfTest: PASS");
    }

    private static void installsAndReadsExactPoliciesWithoutCurrentSemantics() throws Exception {
        Path data = Files.createTempDirectory("rbvm-risk-method-policy-http-");
        MutableStore store = new MutableStore();
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        HttpClient client = client();
        try (CsvPlatformServer server = server(data, ApiKeyAuthenticator.disabled(), Optional.of(api))) {
            server.start();
            URI formulaInstall = installUri(
                    server,
                    1,
                    "RBVM_FORMULA",
                    RbvmFormulaV1.FORMULA_ID,
                    RbvmFormulaV1.FORMULA_VERSION,
                    RbvmFormulaV1.FORMULA_SHA256
            );
            HttpResponse<String> inserted = post(client, formulaInstall);
            assert inserted.statusCode() == 201 : inserted.body();
            assert inserted.body().contains("RBVM_RISK_METHOD_SELECTION_POLICY_INSTALLATION_API_V1");
            assert inserted.body().contains("\"installationStatus\": \"INSERTED\"");
            assert inserted.body().contains("EXACT_REVISION_AND_SHA_NO_CURRENT_LATEST_OR_DEFAULT");
            assert inserted.body().contains("\"methodFamily\": \"RBVM_FORMULA\"");
            String location = inserted.headers().firstValue("Location").orElseThrow();
            String etag = inserted.headers().firstValue("ETag").orElseThrow();
            assert location.startsWith("/api/v1/risk-method-selection-policies/1/");
            assert etag.startsWith("\"risk-method-selection-policy-");

            HttpResponse<String> replay = post(client, formulaInstall);
            assert replay.statusCode() == 200 : replay.body();
            assert replay.body().contains("\"installationStatus\": \"REPLAYED\"");

            HttpResponse<String> read = get(client, server.baseUri().resolve(location));
            assert read.statusCode() == 200 : read.body();
            assert read.body().contains("RBVM_RISK_METHOD_SELECTION_POLICY_API_V1");
            assert read.body().contains("canonicalPayloadBase64");
            assert read.headers().firstValue("ETag").orElseThrow().equals(etag);

            int revision = 2;
            for (RbvmDerivedRiskMethodology.Definition definition
                    : RbvmDerivedRiskMethodologyCatalog.definitions()) {
                HttpResponse<String> derived = post(client, installUri(
                        server,
                        revision++,
                        "STANDARD_DERIVED",
                        definition.methodologyId(),
                        definition.version(),
                        definition.methodologySha256()
                ));
                assert derived.statusCode() == 201 : derived.body();
                assert derived.body().contains("\"methodId\": \""
                        + definition.methodologyId() + "\"");
            }
            assert store.size() == 3;

            HttpResponse<String> health = get(client, server.baseUri().resolve("/api/v1/health"));
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"riskMethodSelectionPolicies\"");
            assert health.body().contains("\"exactReadEnabled\": true");
            assert health.body().contains("\"installationEnabled\": true");

            HttpResponse<String> metrics = get(client, server.baseUri().resolve("/api/v1/metrics"));
            assert metrics.statusCode() == 200 : metrics.body();
            assert metrics.body().contains("rbvm_risk_method_selection_policy_api_enabled 1");
        } finally {
            deleteTree(data);
        }
    }

    private static void rejectsAliasesQueriesBodiesAndWrongMethods() throws Exception {
        Path data = Files.createTempDirectory("rbvm-risk-method-policy-invalid-");
        MutableStore store = new MutableStore();
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        HttpClient client = client();
        RbvmDerivedRiskMethodology.Definition definition =
                RbvmDerivedRiskMethodologyCatalog.definitions().get(0);
        try (CsvPlatformServer server = server(data, ApiKeyAuthenticator.disabled(), Optional.of(api))) {
            server.start();
            URI formulaInstall = installUri(
                    server, 1, "RBVM_FORMULA", RbvmFormulaV1.FORMULA_ID,
                    RbvmFormulaV1.FORMULA_VERSION, RbvmFormulaV1.FORMULA_SHA256
            );
            HttpResponse<String> inserted = post(client, formulaInstall);
            String location = inserted.headers().firstValue("Location").orElseThrow();

            HttpResponse<String> query = get(
                    client,
                    URI.create(server.baseUri().resolve(location).toString() + "?latest=true")
            );
            assert query.statusCode() == 400 : query.body();

            HttpResponse<String> body = client.send(
                    HttpRequest.newBuilder(formulaInstall)
                            .timeout(Duration.ofSeconds(10))
                            .POST(HttpRequest.BodyPublishers.ofString("{}"))
                            .build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert body.statusCode() == 400 : body.body();
            assert body.body().contains("RISK METHOD SELECTION POLICY BODY NOT ALLOWED");

            HttpResponse<String> wrongMethod = get(client, formulaInstall);
            assert wrongMethod.statusCode() == 405 : wrongMethod.body();
            assert wrongMethod.headers().firstValue("Allow").orElseThrow().equals("POST");

            HttpResponse<String> collection = get(
                    client,
                    server.baseUri().resolve("/api/v1/risk-method-selection-policies")
            );
            assert collection.statusCode() == 404 : collection.body();

            URI alias = installUri(
                    server,
                    2,
                    "STANDARD_DERIVED",
                    definition.methodologyId().toLowerCase(),
                    definition.version(),
                    definition.methodologySha256()
            );
            HttpResponse<String> aliasRejected = post(client, alias);
            assert aliasRejected.statusCode() == 404 : aliasRejected.body();
            assert aliasRejected.body().contains("RISK METHOD NOT FOUND");

            HttpResponse<String> conflict = post(client, installUri(
                    server,
                    1,
                    "STANDARD_DERIVED",
                    definition.methodologyId(),
                    definition.version(),
                    definition.methodologySha256()
            ));
            assert conflict.statusCode() == 409 : conflict.body();
            assert conflict.body().contains("RISK METHOD SELECTION POLICY REVISION CONFLICT");
            assert store.size() == 1;
        } finally {
            deleteTree(data);
        }
    }

    private static void protectsDisabledCapabilityBehindAuthorization() throws Exception {
        Path data = Files.createTempDirectory("rbvm-risk-method-policy-auth-");
        String viewerToken = "risk-policy-viewer-token-abcdefghijklmnopqrstuvwxyz-123";
        String operatorToken = "risk-policy-operator-token-abcdefghijklmnopqrstuvwxyz-123";
        Path registry = data.resolve("api-keys.conf");
        Files.writeString(
                registry,
                digest(viewerToken) + "=risk-policy-viewer|VIEWER\n"
                        + digest(operatorToken) + "=risk-policy-operator|OPERATOR\n",
                StandardCharsets.UTF_8
        );
        try {
            Files.setPosixFilePermissions(registry, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystems rely on platform ACLs.
        }

        RbvmRiskMethodSelectionPolicy formula = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data.resolve("evidence"),
                ApiKeyAuthenticator.fromFile(registry),
                Optional.empty()
        )) {
            server.start();
            URI read = server.baseUri().resolve(
                    "/api/v1/risk-method-selection-policies/1/" + formula.policySha256()
            );
            URI write = installUri(
                    server, 1, "RBVM_FORMULA", RbvmFormulaV1.FORMULA_ID,
                    RbvmFormulaV1.FORMULA_VERSION, RbvmFormulaV1.FORMULA_SHA256
            );

            HttpResponse<String> unauthenticatedRead = get(client, read);
            assert unauthenticatedRead.statusCode() == 401 : unauthenticatedRead.body();
            assert !unauthenticatedRead.body().contains("PERSISTENCE UNAVAILABLE");

            HttpResponse<String> viewerRead = authorizedGet(client, read, viewerToken);
            assert viewerRead.statusCode() == 503 : viewerRead.body();
            assert viewerRead.body().contains("RISK METHOD SELECTION POLICY PERSISTENCE UNAVAILABLE");

            HttpResponse<String> viewerWrite = authorizedPost(client, write, viewerToken);
            assert viewerWrite.statusCode() == 403 : viewerWrite.body();
            assert !viewerWrite.body().contains("PERSISTENCE UNAVAILABLE");

            HttpResponse<String> operatorWrite = authorizedPost(client, write, operatorToken);
            assert operatorWrite.statusCode() == 503 : operatorWrite.body();
            assert operatorWrite.body().contains("RISK METHOD SELECTION POLICY PERSISTENCE UNAVAILABLE");
        } finally {
            deleteTree(data);
        }
    }

    private static URI installUri(
            CsvPlatformServer server,
            int revision,
            String family,
            String methodId,
            int methodVersion,
            String methodSha
    ) {
        return server.baseUri().resolve(
                "/api/v1/risk-method-selection-policy-installations/"
                        + revision + "/" + family + "/" + methodId + "/"
                        + methodVersion + "/" + methodSha
        );
    }

    private static CsvPlatformServer server(
            Path data,
            ApiKeyAuthenticator authenticator,
            Optional<RiskMethodSelectionPolicyApi> api
    ) throws Exception {
        CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024,
                new NoopCanonicalProjection(), new InMemoryDomainCatalog(),
                authenticator, RequestRateLimiter.disabled()
        );
        api.ifPresent(server::enableRiskMethodSelectionPolicyApi);
        return server;
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

    private static HttpResponse<String> post(HttpClient client, URI uri) throws Exception {
        return client.send(
                HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10))
                        .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static HttpResponse<String> authorizedGet(HttpClient client, URI uri, String token)
            throws Exception {
        return client.send(
                HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10))
                        .header("Authorization", "Bearer " + token).GET().build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static HttpResponse<String> authorizedPost(HttpClient client, URI uri, String token)
            throws Exception {
        return client.send(
                HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10))
                        .header("Authorization", "Bearer " + token)
                        .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static String digest(String token) throws Exception {
        return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256")
                        .digest(token.getBytes(StandardCharsets.UTF_8))
        );
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted((left, right) -> right.getNameCount() - left.getNameCount())
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (Exception exception) {
                            throw new RuntimeException(exception);
                        }
                    });
        }
    }

    private static final class MutableStore implements RiskMethodSelectionPolicyStore {
        private final Map<Integer, RbvmRiskMethodSelectionPolicy> byRevision = new LinkedHashMap<>();

        @Override
        public RiskMethodSelectionPolicyInstallResult install(RbvmRiskMethodSelectionPolicy policy) {
            RbvmRiskMethodSelectionPolicy existing = byRevision.get(policy.revision());
            if (existing != null) {
                var status = existing.policySha256().equals(policy.policySha256())
                        ? RiskMethodSelectionPolicyInstallResult.Status.REPLAYED
                        : RiskMethodSelectionPolicyInstallResult.Status.REVISION_CONFLICT;
                return new RiskMethodSelectionPolicyInstallResult(
                        status, policy.revision(), policy.policySha256(),
                        existing.revision(), existing.policySha256()
                );
            }
            byRevision.put(policy.revision(), policy);
            return new RiskMethodSelectionPolicyInstallResult(
                    RiskMethodSelectionPolicyInstallResult.Status.INSERTED,
                    policy.revision(), policy.policySha256(),
                    policy.revision(), policy.policySha256()
            );
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByRevision(int revision) {
            return Optional.ofNullable(byRevision.get(revision));
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByPolicySha256(String policySha256) {
            return byRevision.values().stream()
                    .filter(policy -> policy.policySha256().equals(policySha256))
                    .findFirst();
        }

        int size() { return byRevision.size(); }
    }
}
