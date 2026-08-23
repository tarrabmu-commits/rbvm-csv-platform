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
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** End-to-end HTTP proof for resolved explicit active risk-method selection. */
public final class CsvResolvedActiveRiskMethodHttpSelfTest {
    private CsvResolvedActiveRiskMethodHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        resolvesCurrentAndExactActivationWithoutImplicitSelection();
        protectsResolutionCapabilityBehindAuthorization();
        System.out.println("CsvResolvedActiveRiskMethodHttpSelfTest: PASS");
    }

    private static void resolvesCurrentAndExactActivationWithoutImplicitSelection()
            throws Exception {
        Path data = Files.createTempDirectory("rbvm-resolved-risk-method-http-");
        CombinedStore store = new CombinedStore(true);
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        RiskMethodSelectionPolicyApi.Response installed = api.install(
                1,
                "RBVM_FORMULA",
                RbvmFormulaV1.FORMULA_ID,
                RbvmFormulaV1.FORMULA_VERSION,
                RbvmFormulaV1.FORMULA_SHA256
        );
        String policySha = ((Map<?, ?>) installed.body().get("policy"))
                .get("policySha256").toString();
        RiskMethodSelectionPolicyApi.Response activated = api.activate(
                7,
                1,
                policySha,
                "http-resolver-operator",
                Instant.parse("2026-08-23T09:00:00Z")
        );
        String eventSha = ((Map<?, ?>) activated.body().get("activation"))
                .get("eventSha256").toString();

        HttpClient client = client();
        try (CsvPlatformServer server = server(data, ApiKeyAuthenticator.disabled(), api)) {
            server.start();
            URI currentUri = server.baseUri().resolve(
                    "/api/v1/risk-method-selection-policy-activation/current/resolved"
            );
            HttpResponse<String> current = get(client, currentUri);
            assert current.statusCode() == 200 : current.body();
            assert current.body().contains("RBVM_RESOLVED_ACTIVE_RISK_METHOD_API_V1");
            assert current.body().contains(
                    "EXPLICIT_ACTIVATION_TO_EXACT_POLICY_TO_EXACT_METHOD_NO_DEFAULT"
            );
            assert current.body().contains("\"selectionState\": \"ACTIVE\"");
            assert current.body().contains("\"activationRevision\": 7");
            assert current.body().contains(eventSha);
            assert current.body().contains("\"revision\": 1");
            assert current.body().contains(policySha);
            assert current.body().contains("\"methodFamily\": \"RBVM_FORMULA\"");
            assert current.body().contains("\"methodId\": \"" + RbvmFormulaV1.FORMULA_ID + "\"");
            assert current.body().contains("\"methodSha256\": \"" + RbvmFormulaV1.FORMULA_SHA256 + "\"");
            assert current.headers().firstValue("ETag").orElseThrow().equals(
                    "\"risk-method-selection-policy-activation-" + eventSha + "\""
            );
            String exactResolvedPath =
                    "/api/v1/risk-method-selection-policy-activations/7/" + eventSha + "/resolved";
            assert current.headers().firstValue("Location").orElseThrow().equals(exactResolvedPath);

            HttpResponse<String> exact = get(client, server.baseUri().resolve(exactResolvedPath));
            assert exact.statusCode() == 200 : exact.body();
            assert exact.body().equals(current.body());
            assert exact.headers().firstValue("ETag").equals(current.headers().firstValue("ETag"));

            HttpResponse<String> wrongSha = get(
                    client,
                    server.baseUri().resolve(
                            "/api/v1/risk-method-selection-policy-activations/7/"
                                    + "0".repeat(64) + "/resolved"
                    )
            );
            assert wrongSha.statusCode() == 404 : wrongSha.body();

            HttpResponse<String> query = get(
                    client,
                    URI.create(currentUri.toString() + "?latest=true")
            );
            assert query.statusCode() == 400 : query.body();

            HttpResponse<String> wrongMethod = post(client, currentUri);
            assert wrongMethod.statusCode() == 405 : wrongMethod.body();
            assert wrongMethod.headers().firstValue("Allow").orElseThrow().equals("GET");

            api.clearActivation(
                    8,
                    "http-resolver-operator",
                    Instant.parse("2026-08-23T09:01:00Z")
            );
            HttpResponse<String> cleared = get(client, currentUri);
            assert cleared.statusCode() == 200 : cleared.body();
            assert cleared.body().contains("\"selectionState\": \"CLEARED\"");
            assert cleared.body().contains("\"policy\": null");
            assert cleared.body().contains("\"selectedMethod\": null");
            assert cleared.body().contains("\"activationRevision\": 8");
        } finally {
            deleteTree(data);
        }
    }

    private static void protectsResolutionCapabilityBehindAuthorization() throws Exception {
        Path data = Files.createTempDirectory("rbvm-resolved-risk-method-auth-");
        String viewerToken = "resolved-risk-viewer-token-abcdefghijklmnopqrstuvwxyz-123";
        Path registry = data.resolve("api-keys.conf");
        Files.writeString(
                registry,
                digest(viewerToken) + "=resolved-risk-viewer|VIEWER\n",
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

        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(new CombinedStore(false));
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data.resolve("evidence"),
                ApiKeyAuthenticator.fromFile(registry),
                api
        )) {
            server.start();
            URI resolved = server.baseUri().resolve(
                    "/api/v1/risk-method-selection-policy-activation/current/resolved"
            );
            HttpResponse<String> unauthenticated = get(client, resolved);
            assert unauthenticated.statusCode() == 401 : unauthenticated.body();
            assert !unauthenticated.body().contains("ACTIVATION PERSISTENCE UNAVAILABLE");

            HttpResponse<String> viewer = authorizedGet(client, resolved, viewerToken);
            assert viewer.statusCode() == 503 : viewer.body();
            assert viewer.body().contains("ACTIVATION PERSISTENCE UNAVAILABLE");
        } finally {
            deleteTree(data);
        }
    }

    private static CsvPlatformServer server(
            Path data,
            ApiKeyAuthenticator authenticator,
            RiskMethodSelectionPolicyApi api
    ) throws Exception {
        CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024,
                new NoopCanonicalProjection(), new InMemoryDomainCatalog(),
                authenticator, RequestRateLimiter.disabled()
        );
        server.enableRiskMethodSelectionPolicyApi(api);
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
                        status,
                        policy.revision(),
                        policy.policySha256(),
                        existing.revision(),
                        existing.policySha256()
                );
            }
            policies.put(policy.revision(), policy);
            return new RiskMethodSelectionPolicyInstallResult(
                    RiskMethodSelectionPolicyInstallResult.Status.INSERTED,
                    policy.revision(),
                    policy.policySha256(),
                    policy.revision(),
                    policy.policySha256()
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
        private final Map<String, RbvmRiskMethodSelectionPolicyActivationEvent> bySha =
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
                        status,
                        event.activationRevision(),
                        event.eventSha256(),
                        same.activationRevision(),
                        same.eventSha256()
                );
            }
            RbvmRiskMethodSelectionPolicyActivationEvent current = current().orElse(null);
            if (current != null && event.activationRevision() < current.activationRevision()) {
                return new RiskMethodSelectionPolicyActivationInstallResult(
                        RiskMethodSelectionPolicyActivationInstallResult.Status.STALE_ACTIVATION_REVISION,
                        event.activationRevision(),
                        event.eventSha256(),
                        current.activationRevision(),
                        current.eventSha256()
                );
            }
            byRevision.put(event.activationRevision(), event);
            bySha.put(event.eventSha256(), event);
            return new RiskMethodSelectionPolicyActivationInstallResult(
                    RiskMethodSelectionPolicyActivationInstallResult.Status.INSERTED,
                    event.activationRevision(),
                    event.eventSha256(),
                    event.activationRevision(),
                    event.eventSha256()
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
            return Optional.ofNullable(bySha.get(eventSha256));
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
