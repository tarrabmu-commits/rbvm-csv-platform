package io.rbvm.csv;

import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;
import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.RiskMethodSelectionPolicyActivationInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyActivationStore;
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
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** End-to-end HTTP proof for explicit V26 risk-method policy activation transport. */
public final class CsvRiskMethodSelectionPolicyActivationHttpSelfTest {
    private CsvRiskMethodSelectionPolicyActivationHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        activatesReplaysReadsAndClearsExactEvents();
        rejectsImplicitOrMalformedActivationSelectors();
        protectsV26CapabilityBehindAuthorization();
        System.out.println("CsvRiskMethodSelectionPolicyActivationHttpSelfTest: PASS");
    }

    private static void activatesReplaysReadsAndClearsExactEvents() throws Exception {
        Path data = Files.createTempDirectory("rbvm-risk-method-activation-http-");
        CombinedStore store = new CombinedStore(true);
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        HttpClient client = client();
        try (CsvPlatformServer server = server(data, ApiKeyAuthenticator.disabled(), Optional.of(api))) {
            server.start();
            HttpResponse<String> policy = post(client, policyInstall(server, 1));
            assert policy.statusCode() == 201 : policy.body();
            String policyLocation = policy.headers().firstValue("Location").orElseThrow();
            String policySha = policyLocation.substring(policyLocation.lastIndexOf('/') + 1);

            URI activeUri = server.baseUri().resolve(
                    "/api/v1/risk-method-selection-policy-activation-events/1/ACTIVE/1/"
                            + policySha + "/2026-08-23T05:00:00Z"
            );
            HttpResponse<String> inserted = post(client, activeUri);
            assert inserted.statusCode() == 201 : inserted.body();
            assert inserted.body().contains("RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_INSTALLATION_API_V1");
            assert inserted.body().contains("\"installationStatus\": \"INSERTED\"");
            assert inserted.body().contains("\"activationState\": \"ACTIVE\"");
            assert inserted.body().contains("\"policyRevision\": 1");
            assert inserted.body().contains(policySha);
            assert inserted.body().contains("CURRENT_IS_GREATEST_EXPLICIT_ACTIVATION_REVISION_NEVER_POLICY_REVISION");
            String activationLocation = inserted.headers().firstValue("Location").orElseThrow();
            String activationEtag = inserted.headers().firstValue("ETag").orElseThrow();
            assert activationLocation.startsWith(
                    "/api/v1/risk-method-selection-policy-activations/1/"
            );
            assert activationEtag.startsWith(
                    "\"risk-method-selection-policy-activation-"
            );

            HttpResponse<String> replay = post(client, activeUri);
            assert replay.statusCode() == 200 : replay.body();
            assert replay.body().contains("\"installationStatus\": \"REPLAYED\"");

            HttpResponse<String> exact = get(client, server.baseUri().resolve(activationLocation));
            assert exact.statusCode() == 200 : exact.body();
            assert exact.body().contains("RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_API_V1");
            assert exact.headers().firstValue("ETag").orElseThrow().equals(activationEtag);

            HttpResponse<String> current = get(
                    client,
                    server.baseUri().resolve("/api/v1/risk-method-selection-policy-activation/current")
            );
            assert current.statusCode() == 200 : current.body();
            assert current.body().contains("\"activationRevision\": 1");
            assert current.body().contains("\"activationState\": \"ACTIVE\"");

            URI clearUri = server.baseUri().resolve(
                    "/api/v1/risk-method-selection-policy-activation-events/2/CLEARED/"
                            + "2026-08-23T05:01:00Z"
            );
            HttpResponse<String> cleared = post(client, clearUri);
            assert cleared.statusCode() == 201 : cleared.body();
            assert cleared.body().contains("\"activationState\": \"CLEARED\"");
            assert cleared.body().contains("\"policyRevision\": null");
            assert cleared.body().contains("\"policySha256\": null");

            HttpResponse<String> currentCleared = get(
                    client,
                    server.baseUri().resolve("/api/v1/risk-method-selection-policy-activation/current")
            );
            assert currentCleared.statusCode() == 200 : currentCleared.body();
            assert currentCleared.body().contains("\"activationRevision\": 2");
            assert currentCleared.body().contains("\"activationState\": \"CLEARED\"");
        } finally {
            deleteTree(data);
        }
    }

    private static void rejectsImplicitOrMalformedActivationSelectors() throws Exception {
        Path data = Files.createTempDirectory("rbvm-risk-method-activation-invalid-");
        CombinedStore store = new CombinedStore(true);
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        HttpClient client = client();
        try (CsvPlatformServer server = server(data, ApiKeyAuthenticator.disabled(), Optional.of(api))) {
            server.start();
            HttpResponse<String> never = get(
                    client,
                    server.baseUri().resolve("/api/v1/risk-method-selection-policy-activation/current")
            );
            assert never.statusCode() == 404 : never.body();
            assert never.body().contains("RISK METHOD SELECTION POLICY ACTIVATION NOT FOUND");

            HttpResponse<String> policy = post(client, policyInstall(server, 1));
            String policyLocation = policy.headers().firstValue("Location").orElseThrow();
            String policySha = policyLocation.substring(policyLocation.lastIndexOf('/') + 1);

            URI malformedTime = server.baseUri().resolve(
                    "/api/v1/risk-method-selection-policy-activation-events/1/ACTIVE/1/"
                            + policySha + "/not-a-time"
            );
            HttpResponse<String> badTime = post(client, malformedTime);
            assert badTime.statusCode() == 400 : badTime.body();
            assert badTime.body().contains("INVALID RISK METHOD SELECTION POLICY ACTIVATION IDENTITY");

            URI missingPolicy = server.baseUri().resolve(
                    "/api/v1/risk-method-selection-policy-activation-events/1/ACTIVE/2/"
                            + "0".repeat(64) + "/2026-08-23T06:00:00Z"
            );
            HttpResponse<String> missing = post(client, missingPolicy);
            assert missing.statusCode() == 404 : missing.body();
            assert missing.body().contains("RISK METHOD SELECTION POLICY NOT FOUND");

            URI active = server.baseUri().resolve(
                    "/api/v1/risk-method-selection-policy-activation-events/5/ACTIVE/1/"
                            + policySha + "/2026-08-23T06:01:00Z"
            );
            assert post(client, active).statusCode() == 201;

            URI conflict = server.baseUri().resolve(
                    "/api/v1/risk-method-selection-policy-activation-events/5/CLEARED/"
                            + "2026-08-23T06:02:00Z"
            );
            HttpResponse<String> conflictResponse = post(client, conflict);
            assert conflictResponse.statusCode() == 409 : conflictResponse.body();
            assert conflictResponse.body().contains("ACTIVATION REVISION CONFLICT");

            URI stale = server.baseUri().resolve(
                    "/api/v1/risk-method-selection-policy-activation-events/4/CLEARED/"
                            + "2026-08-23T06:03:00Z"
            );
            HttpResponse<String> staleResponse = post(client, stale);
            assert staleResponse.statusCode() == 409 : staleResponse.body();
            assert staleResponse.body().contains("STALE RISK METHOD SELECTION POLICY ACTIVATION REVISION");

            HttpResponse<String> query = get(
                    client,
                    URI.create(server.baseUri().resolve(
                            "/api/v1/risk-method-selection-policy-activation/current"
                    ) + "?latest=true")
            );
            assert query.statusCode() == 400 : query.body();

            HttpResponse<String> wrongMethod = get(client, active);
            assert wrongMethod.statusCode() == 405 : wrongMethod.body();
            assert wrongMethod.headers().firstValue("Allow").orElseThrow().equals("POST");

            HttpResponse<String> collection = get(
                    client,
                    server.baseUri().resolve("/api/v1/risk-method-selection-policy-activations")
            );
            assert collection.statusCode() == 404 : collection.body();
        } finally {
            deleteTree(data);
        }
    }

    private static void protectsV26CapabilityBehindAuthorization() throws Exception {
        Path data = Files.createTempDirectory("rbvm-risk-method-activation-auth-");
        String viewerToken = "activation-viewer-token-abcdefghijklmnopqrstuvwxyz-123";
        String operatorToken = "activation-operator-token-abcdefghijklmnopqrstuvwxyz-123";
        Path registry = data.resolve("api-keys.conf");
        Files.writeString(
                registry,
                digest(viewerToken) + "=activation-viewer|VIEWER\n"
                        + digest(operatorToken) + "=activation-operator|OPERATOR\n",
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

        CombinedStore v25Only = new CombinedStore(false);
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(v25Only);
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data.resolve("evidence"),
                ApiKeyAuthenticator.fromFile(registry),
                Optional.of(api)
        )) {
            server.start();
            URI read = server.baseUri().resolve(
                    "/api/v1/risk-method-selection-policy-activation/current"
            );
            URI write = server.baseUri().resolve(
                    "/api/v1/risk-method-selection-policy-activation-events/1/CLEARED/"
                            + "2026-08-23T07:00:00Z"
            );

            HttpResponse<String> unauthenticatedRead = get(client, read);
            assert unauthenticatedRead.statusCode() == 401 : unauthenticatedRead.body();
            assert !unauthenticatedRead.body().contains("ACTIVATION PERSISTENCE UNAVAILABLE");

            HttpResponse<String> viewerRead = authorizedGet(client, read, viewerToken);
            assert viewerRead.statusCode() == 503 : viewerRead.body();
            assert viewerRead.body().contains("ACTIVATION PERSISTENCE UNAVAILABLE");

            HttpResponse<String> viewerWrite = authorizedPost(client, write, viewerToken);
            assert viewerWrite.statusCode() == 403 : viewerWrite.body();
            assert !viewerWrite.body().contains("ACTIVATION PERSISTENCE UNAVAILABLE");

            HttpResponse<String> operatorWrite = authorizedPost(client, write, operatorToken);
            assert operatorWrite.statusCode() == 503 : operatorWrite.body();
            assert operatorWrite.body().contains("ACTIVATION PERSISTENCE UNAVAILABLE");
        } finally {
            deleteTree(data);
        }
    }

    private static URI policyInstall(CsvPlatformServer server, int revision) {
        return server.baseUri().resolve(
                "/api/v1/risk-method-selection-policy-installations/" + revision
                        + "/RBVM_FORMULA/" + RbvmFormulaV1.FORMULA_ID + "/"
                        + RbvmFormulaV1.FORMULA_VERSION + "/" + RbvmFormulaV1.FORMULA_SHA256
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

    private static final class CombinedStore implements RiskMethodSelectionPolicyStore {
        private final Map<Integer, RbvmRiskMethodSelectionPolicy> policies = new LinkedHashMap<>();
        private final ActivationStore activations = new ActivationStore();
        private final boolean activationEnabled;

        private CombinedStore(boolean activationEnabled) {
            this.activationEnabled = activationEnabled;
        }

        @Override
        public RiskMethodSelectionPolicyInstallResult install(RbvmRiskMethodSelectionPolicy policy) {
            RbvmRiskMethodSelectionPolicy existing = policies.get(policy.revision());
            if (existing != null) {
                var status = existing.policySha256().equals(policy.policySha256())
                        ? RiskMethodSelectionPolicyInstallResult.Status.REPLAYED
                        : RiskMethodSelectionPolicyInstallResult.Status.REVISION_CONFLICT;
                return new RiskMethodSelectionPolicyInstallResult(
                        status, policy.revision(), policy.policySha256(),
                        existing.revision(), existing.policySha256()
                );
            }
            policies.put(policy.revision(), policy);
            return new RiskMethodSelectionPolicyInstallResult(
                    RiskMethodSelectionPolicyInstallResult.Status.INSERTED,
                    policy.revision(), policy.policySha256(),
                    policy.revision(), policy.policySha256()
            );
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByRevision(int revision) {
            return Optional.ofNullable(policies.get(revision));
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByPolicySha256(String policySha256) {
            return policies.values().stream()
                    .filter(policy -> policy.policySha256().equals(policySha256))
                    .findFirst();
        }

        @Override
        public Optional<RiskMethodSelectionPolicyActivationStore> activationStore() {
            return activationEnabled ? Optional.of(activations) : Optional.empty();
        }
    }

    private static final class ActivationStore implements RiskMethodSelectionPolicyActivationStore {
        private final Map<Integer, RbvmRiskMethodSelectionPolicyActivationEvent> byRevision =
                new LinkedHashMap<>();

        @Override
        public RiskMethodSelectionPolicyActivationInstallResult install(
                RbvmRiskMethodSelectionPolicyActivationEvent event
        ) {
            RbvmRiskMethodSelectionPolicyActivationEvent same = byRevision.get(event.activationRevision());
            if (same != null) {
                var status = same.eventSha256().equals(event.eventSha256())
                        ? RiskMethodSelectionPolicyActivationInstallResult.Status.REPLAYED
                        : RiskMethodSelectionPolicyActivationInstallResult.Status.REVISION_CONFLICT;
                return new RiskMethodSelectionPolicyActivationInstallResult(
                        status, event.activationRevision(), event.eventSha256(),
                        same.activationRevision(), same.eventSha256()
                );
            }
            RbvmRiskMethodSelectionPolicyActivationEvent current = current().orElse(null);
            if (current != null && event.activationRevision() < current.activationRevision()) {
                return new RiskMethodSelectionPolicyActivationInstallResult(
                        RiskMethodSelectionPolicyActivationInstallResult.Status.STALE_ACTIVATION_REVISION,
                        event.activationRevision(), event.eventSha256(),
                        current.activationRevision(), current.eventSha256()
                );
            }
            byRevision.put(event.activationRevision(), event);
            return new RiskMethodSelectionPolicyActivationInstallResult(
                    RiskMethodSelectionPolicyActivationInstallResult.Status.INSERTED,
                    event.activationRevision(), event.eventSha256(),
                    event.activationRevision(), event.eventSha256()
            );
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByActivationRevision(
                int activationRevision
        ) {
            return Optional.ofNullable(byRevision.get(activationRevision));
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByEventSha256(
                String eventSha256
        ) {
            return byRevision.values().stream()
                    .filter(event -> event.eventSha256().equals(eventSha256))
                    .findFirst();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> current() {
            return byRevision.values().stream().max(
                    Comparator.comparingInt(
                            RbvmRiskMethodSelectionPolicyActivationEvent::activationRevision
                    )
            );
        }
    }
}
