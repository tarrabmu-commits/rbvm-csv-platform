package io.rbvm.csv;

import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding;
import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding.ResultFamily;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy.MethodFamily;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;
import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.ActiveRiskMethodExecutionBindingInstallResult;
import io.rbvm.postgres.ActiveRiskMethodExecutionBindingStore;
import io.rbvm.postgres.ActiveRiskMethodNativeResult;
import io.rbvm.postgres.ActiveRiskMethodResultMaterializer;
import io.rbvm.postgres.DefaultActiveRiskMethodExecutionBindingMaterializer;
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
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** End-to-end socket proof for exact V27 active-risk-method execution transport. */
public final class CsvActiveRiskMethodExecutionHttpSelfTest {
    private static final String INPUT_SHA = "0".repeat(64);

    private CsvActiveRiskMethodExecutionHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        executesReplaysAndReadsExactBinding();
        rejectsCurrentQueriesBodiesAndWrongMethods();
        protectsV27CapabilityBehindAuthorization();
        System.out.println("CsvActiveRiskMethodExecutionHttpSelfTest: PASS");
    }

    private static void executesReplaysAndReadsExactBinding() throws Exception {
        Path data = Files.createTempDirectory("rbvm-active-risk-execution-http-");
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RbvmRiskMethodSelectionPolicyActivationEvent activation = active(7, policy);
        ApiFixture fixture = api(policy, activation, "1".repeat(64));
        HttpClient client = client();
        try (CsvPlatformServer server = server(data, ApiKeyAuthenticator.disabled(), Optional.of(fixture.api()))) {
            server.start();
            URI execution = execution(server, activation);
            HttpResponse<String> inserted = post(client, execution);
            assert inserted.statusCode() == 201 : inserted.body();
            assert inserted.body().contains("RBVM_ACTIVE_RISK_METHOD_EXECUTION_API_V1");
            assert inserted.body().contains("\"executionStatus\": \"INSERTED\"");
            assert inserted.body().contains("\"activationRevision\": 7");
            assert inserted.body().contains(activation.eventSha256());
            assert inserted.body().contains(policy.policySha256());
            assert inserted.body().contains("\"methodFamily\": \"RBVM_FORMULA\"");
            assert inserted.body().contains("\"inputSnapshotSha256\": \"" + INPUT_SHA + "\"");
            assert inserted.body().contains("\"resultFamily\": \"RBVM_FORMULA_RESULT\"");
            assert inserted.body().contains("/api/v1/formula-results/" + "1".repeat(64));
            String location = inserted.headers().firstValue("Location").orElseThrow();
            String etag = inserted.headers().firstValue("ETag").orElseThrow();
            assert location.startsWith("/api/v1/active-risk-method-execution-bindings/");
            assert etag.startsWith("\"active-risk-method-execution-binding-");
            assert fixture.results().calls == 1;

            HttpResponse<String> replay = post(client, execution);
            assert replay.statusCode() == 200 : replay.body();
            assert replay.body().contains("\"executionStatus\": \"REPLAYED\"");
            assert fixture.results().calls == 1 : "HTTP replay must not re-execute risk method";

            HttpResponse<String> exact = get(client, server.baseUri().resolve(location));
            assert exact.statusCode() == 200 : exact.body();
            assert exact.headers().firstValue("ETag").orElseThrow().equals(etag);
            assert !exact.body().contains("executionStatus");
        } finally {
            deleteTree(data);
        }
    }

    private static void rejectsCurrentQueriesBodiesAndWrongMethods() throws Exception {
        Path data = Files.createTempDirectory("rbvm-active-risk-execution-invalid-");
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RbvmRiskMethodSelectionPolicyActivationEvent activation = active(8, policy);
        ApiFixture fixture = api(policy, activation, "2".repeat(64));
        HttpClient client = client();
        try (CsvPlatformServer server = server(data, ApiKeyAuthenticator.disabled(), Optional.of(fixture.api()))) {
            server.start();
            URI execution = execution(server, activation);

            HttpResponse<String> query = post(
                    client,
                    URI.create(execution.toString() + "?current=true")
            );
            assert query.statusCode() == 400 : query.body();
            assert query.body().contains("INVALID ACTIVE RISK METHOD EXECUTION QUERY");

            HttpResponse<String> body = client.send(
                    HttpRequest.newBuilder(execution).timeout(Duration.ofSeconds(10))
                            .POST(HttpRequest.BodyPublishers.ofString("{}"))
                            .build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert body.statusCode() == 400 : body.body();
            assert body.body().contains("ACTIVE RISK METHOD EXECUTION BODY NOT ALLOWED");

            HttpResponse<String> wrongMethod = get(client, execution);
            assert wrongMethod.statusCode() == 405 : wrongMethod.body();
            assert wrongMethod.headers().firstValue("Allow").orElseThrow().equals("POST");

            HttpResponse<String> current = post(
                    client,
                    server.baseUri().resolve(
                            "/api/v1/active-risk-method-executions/current/"
                                    + activation.eventSha256() + "/" + INPUT_SHA
                    )
            );
            assert current.statusCode() == 404 : current.body();

            HttpResponse<String> collection = get(
                    client,
                    server.baseUri().resolve("/api/v1/active-risk-method-execution-bindings")
            );
            assert collection.statusCode() == 404 : collection.body();
        } finally {
            deleteTree(data);
        }
    }

    private static void protectsV27CapabilityBehindAuthorization() throws Exception {
        Path data = Files.createTempDirectory("rbvm-active-risk-execution-auth-");
        String viewerToken = "execution-viewer-token-abcdefghijklmnopqrstuvwxyz-123";
        String operatorToken = "execution-operator-token-abcdefghijklmnopqrstuvwxyz-123";
        Path registry = data.resolve("api-keys.conf");
        Files.writeString(
                registry,
                digest(viewerToken) + "=execution-viewer|VIEWER\n"
                        + digest(operatorToken) + "=execution-operator|OPERATOR\n",
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

        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data.resolve("evidence"),
                ApiKeyAuthenticator.fromFile(registry),
                Optional.empty()
        )) {
            server.start();
            URI execution = server.baseUri().resolve(
                    "/api/v1/active-risk-method-executions/1/"
                            + "1".repeat(64) + "/" + INPUT_SHA
            );
            URI binding = server.baseUri().resolve(
                    "/api/v1/active-risk-method-execution-bindings/" + "2".repeat(64)
            );

            HttpResponse<String> unauthenticatedExecution = post(client, execution);
            assert unauthenticatedExecution.statusCode() == 401 : unauthenticatedExecution.body();
            assert !unauthenticatedExecution.body().contains("EXECUTION PERSISTENCE UNAVAILABLE");

            HttpResponse<String> viewerExecution = authorizedPost(client, execution, viewerToken);
            assert viewerExecution.statusCode() == 403 : viewerExecution.body();
            assert !viewerExecution.body().contains("EXECUTION PERSISTENCE UNAVAILABLE");

            HttpResponse<String> operatorExecution = authorizedPost(client, execution, operatorToken);
            assert operatorExecution.statusCode() == 503 : operatorExecution.body();
            assert operatorExecution.body().contains("EXECUTION PERSISTENCE UNAVAILABLE");

            HttpResponse<String> unauthenticatedRead = get(client, binding);
            assert unauthenticatedRead.statusCode() == 401 : unauthenticatedRead.body();
            HttpResponse<String> viewerRead = authorizedGet(client, binding, viewerToken);
            assert viewerRead.statusCode() == 503 : viewerRead.body();
        } finally {
            deleteTree(data);
        }
    }

    private static ApiFixture api(
            RbvmRiskMethodSelectionPolicy policy,
            RbvmRiskMethodSelectionPolicyActivationEvent activation,
            String resultSha
    ) {
        MemoryBindingStore bindings = new MemoryBindingStore();
        CountingResultMaterializer results = new CountingResultMaterializer(resultSha);
        DefaultActiveRiskMethodExecutionBindingMaterializer materializer =
                new DefaultActiveRiskMethodExecutionBindingMaterializer(
                        new ExactPolicyStore(policy),
                        new ExactActivationStore(activation),
                        results,
                        bindings
                );
        return new ApiFixture(new ActiveRiskMethodExecutionApi(bindings, materializer), results);
    }

    private static RbvmRiskMethodSelectionPolicyActivationEvent active(
            int activationRevision,
            RbvmRiskMethodSelectionPolicy policy
    ) {
        return RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                activationRevision,
                policy,
                "execution-http-test",
                "",
                Instant.parse("2026-08-23T08:30:00Z").plusSeconds(activationRevision)
        );
    }

    private static URI execution(
            CsvPlatformServer server,
            RbvmRiskMethodSelectionPolicyActivationEvent activation
    ) {
        return server.baseUri().resolve(
                "/api/v1/active-risk-method-executions/" + activation.activationRevision()
                        + "/" + activation.eventSha256() + "/" + INPUT_SHA
        );
    }

    private static CsvPlatformServer server(
            Path data,
            ApiKeyAuthenticator authenticator,
            Optional<ActiveRiskMethodExecutionApi> api
    ) throws Exception {
        CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024,
                new NoopCanonicalProjection(), new InMemoryDomainCatalog(),
                authenticator, RequestRateLimiter.disabled()
        );
        api.ifPresent(server::enableActiveRiskMethodExecutionApi);
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
                MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8))
        );
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (Exception exception) {
                    throw new RuntimeException(exception);
                }
            });
        }
    }

    private record ApiFixture(
            ActiveRiskMethodExecutionApi api,
            CountingResultMaterializer results
    ) {
    }

    private static final class ExactPolicyStore implements RiskMethodSelectionPolicyStore {
        private final RbvmRiskMethodSelectionPolicy policy;

        private ExactPolicyStore(RbvmRiskMethodSelectionPolicy policy) { this.policy = policy; }

        @Override
        public RiskMethodSelectionPolicyInstallResult install(RbvmRiskMethodSelectionPolicy ignored) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByRevision(int revision) {
            return policy.revision() == revision ? Optional.of(policy) : Optional.empty();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByPolicySha256(String policySha256) {
            return policy.policySha256().equals(policySha256) ? Optional.of(policy) : Optional.empty();
        }
    }

    private static final class ExactActivationStore implements RiskMethodSelectionPolicyActivationStore {
        private final RbvmRiskMethodSelectionPolicyActivationEvent activation;

        private ExactActivationStore(RbvmRiskMethodSelectionPolicyActivationEvent activation) {
            this.activation = activation;
        }

        @Override
        public RiskMethodSelectionPolicyActivationInstallResult install(
                RbvmRiskMethodSelectionPolicyActivationEvent ignored
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByActivationRevision(
                int revision
        ) {
            return activation.activationRevision() == revision
                    ? Optional.of(activation) : Optional.empty();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByEventSha256(String sha) {
            return activation.eventSha256().equals(sha) ? Optional.of(activation) : Optional.empty();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> current() {
            throw new AssertionError("execution HTTP transport must never resolve current activation");
        }
    }

    private static final class CountingResultMaterializer implements ActiveRiskMethodResultMaterializer {
        private final String resultSha;
        private int calls;

        private CountingResultMaterializer(String resultSha) { this.resultSha = resultSha; }

        @Override
        public ActiveRiskMethodNativeResult materialize(
                RbvmRiskMethodSelectionPolicy policy,
                String inputSnapshotSha256
        ) {
            calls++;
            return new ActiveRiskMethodNativeResult(
                    inputSnapshotSha256,
                    policy.methodFamily(),
                    policy.methodId(),
                    policy.methodVersion(),
                    policy.methodSha256(),
                    policy.methodFamily() == MethodFamily.RBVM_FORMULA
                            ? ResultFamily.RBVM_FORMULA_RESULT
                            : ResultFamily.DERIVED_RISK_RESULT,
                    resultSha
            );
        }
    }

    private static final class MemoryBindingStore implements ActiveRiskMethodExecutionBindingStore {
        private final Map<String, RbvmActiveRiskMethodExecutionBinding> bySha = new HashMap<>();
        private final Map<String, RbvmActiveRiskMethodExecutionBinding> byExecution = new HashMap<>();

        @Override
        public ActiveRiskMethodExecutionBindingInstallResult install(
                RbvmActiveRiskMethodExecutionBinding binding
        ) {
            String key = binding.activationEventSha256() + ':' + binding.inputSnapshotSha256();
            RbvmActiveRiskMethodExecutionBinding existing = byExecution.get(key);
            if (existing != null) {
                return new ActiveRiskMethodExecutionBindingInstallResult(
                        existing.bindingSha256().equals(binding.bindingSha256())
                                ? ActiveRiskMethodExecutionBindingInstallResult.Status.REPLAYED
                                : ActiveRiskMethodExecutionBindingInstallResult.Status.EXECUTION_CONFLICT,
                        binding.bindingSha256(),
                        existing.bindingSha256()
                );
            }
            bySha.put(binding.bindingSha256(), binding);
            byExecution.put(key, binding);
            return new ActiveRiskMethodExecutionBindingInstallResult(
                    ActiveRiskMethodExecutionBindingInstallResult.Status.INSERTED,
                    binding.bindingSha256(),
                    binding.bindingSha256()
            );
        }

        @Override
        public Optional<RbvmActiveRiskMethodExecutionBinding> findByBindingSha256(String sha) {
            return Optional.ofNullable(bySha.get(sha));
        }

        @Override
        public Optional<RbvmActiveRiskMethodExecutionBinding> findByActivationAndInput(
                String activationEventSha256,
                String inputSnapshotSha256
        ) {
            return Optional.ofNullable(byExecution.get(activationEventSha256 + ':' + inputSnapshotSha256));
        }
    }
}
