package io.rbvm.csv;

import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding;
import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding.ResultFamily;
import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy.MethodFamily;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;
import io.rbvm.postgres.ActiveRiskMethodExecutionBindingInstallResult;
import io.rbvm.postgres.ActiveRiskMethodExecutionBindingStore;
import io.rbvm.postgres.ActiveRiskMethodNativeResult;
import io.rbvm.postgres.ActiveRiskMethodResultMaterializer;
import io.rbvm.postgres.DefaultActiveRiskMethodExecutionBindingMaterializer;
import io.rbvm.postgres.RiskMethodSelectionPolicyActivationInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyActivationStore;
import io.rbvm.postgres.RiskMethodSelectionPolicyInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyStore;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public final class ActiveRiskMethodExecutionApiSelfTest {
    private static final String INPUT_SHA = "0".repeat(64);

    private ActiveRiskMethodExecutionApiSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        executesExactFormulaAndReplaysBindingWithoutReexecution();
        exposesExactDerivedResultLocation();
        rejectsInvalidMissingWrongAndClearedIdentities();
        System.out.println("ActiveRiskMethodExecutionApiSelfTest: PASS");
    }

    private static void executesExactFormulaAndReplaysBindingWithoutReexecution()
            throws Exception {
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RbvmRiskMethodSelectionPolicyActivationEvent activation = active(7, policy);
        Fixture fixture = fixture(policy, activation, "1".repeat(64));

        ActiveRiskMethodExecutionApi.Response inserted = fixture.api().execute(
                7,
                activation.eventSha256(),
                INPUT_SHA
        );
        assert inserted.status() == 201;
        assert inserted.body().get("contractId").equals(ActiveRiskMethodExecutionApi.CONTRACT_ID);
        assert inserted.body().get("executionSemantics")
                .equals(ActiveRiskMethodExecutionApi.EXECUTION_SEMANTICS);
        assert inserted.body().get("executionStatus").equals("INSERTED");
        assert inserted.body().get("resultLocation")
                .equals("/api/v1/formula-results/" + "1".repeat(64));

        @SuppressWarnings("unchecked")
        Map<String, Object> binding = (Map<String, Object>) inserted.body().get("binding");
        String bindingSha = (String) binding.get("bindingSha256");
        assert binding.get("activationRevision").equals(7);
        assert binding.get("activationEventSha256").equals(activation.eventSha256());
        assert binding.get("policyRevision").equals(1);
        assert binding.get("policySha256").equals(policy.policySha256());
        assert binding.get("selectionRole").equals("PRIMARY");
        assert binding.get("methodFamily").equals("RBVM_FORMULA");
        assert binding.get("methodId").equals(policy.methodId());
        assert binding.get("methodVersion").equals(policy.methodVersion());
        assert binding.get("methodSha256").equals(policy.methodSha256());
        assert binding.get("inputSnapshotSha256").equals(INPUT_SHA);
        assert binding.get("resultFamily").equals("RBVM_FORMULA_RESULT");
        assert binding.get("resultSha256").equals("1".repeat(64));
        assert Base64.getDecoder().decode((String) binding.get("canonicalPayloadBase64")).length > 0;
        assert inserted.headers().get("ETag").equals(
                ActiveRiskMethodExecutionApi.strongEtag(bindingSha)
        );
        assert inserted.headers().get("Location").equals(
                "/api/v1/active-risk-method-execution-bindings/" + bindingSha
        );
        assert fixture.results().calls == 1;

        ActiveRiskMethodExecutionApi.Response replayed = fixture.api().execute(
                7,
                activation.eventSha256(),
                INPUT_SHA
        );
        assert replayed.status() == 200;
        assert replayed.body().get("executionStatus").equals("REPLAYED");
        assert fixture.results().calls == 1 : "binding replay must not execute the method again";

        ActiveRiskMethodExecutionApi.Response exact = fixture.api().getBinding(bindingSha);
        assert exact.status() == 200;
        assert !exact.body().containsKey("executionStatus");
        assert exact.headers().get("ETag").equals(inserted.headers().get("ETag"));
    }

    private static void exposesExactDerivedResultLocation() throws Exception {
        RbvmDerivedRiskMethodology.Definition definition =
                RbvmDerivedRiskMethodologyCatalog.definitions().get(0);
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.derived(2, definition);
        RbvmRiskMethodSelectionPolicyActivationEvent activation = active(8, policy);
        Fixture fixture = fixture(policy, activation, "2".repeat(64));

        ActiveRiskMethodExecutionApi.Response response = fixture.api().execute(
                8,
                activation.eventSha256(),
                INPUT_SHA
        );
        assert response.status() == 201;
        assert response.body().get("resultLocation")
                .equals("/api/v1/derived-risk-results/" + "2".repeat(64));
        @SuppressWarnings("unchecked")
        Map<String, Object> binding = (Map<String, Object>) response.body().get("binding");
        assert binding.get("methodFamily").equals("STANDARD_DERIVED");
        assert binding.get("methodId").equals(definition.methodologyId());
        assert binding.get("methodSha256").equals(definition.methodologySha256());
        assert binding.get("resultFamily").equals("DERIVED_RISK_RESULT");
    }

    private static void rejectsInvalidMissingWrongAndClearedIdentities() throws Exception {
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RbvmRiskMethodSelectionPolicyActivationEvent activation = active(9, policy);
        Fixture fixture = fixture(policy, activation, "3".repeat(64));

        expectProblem(400, "INVALID_ACTIVE_RISK_METHOD_EXECUTION_IDENTITY",
                () -> fixture.api().getBinding("ABC"));
        expectProblem(404, "ACTIVE_RISK_METHOD_EXECUTION_BINDING_NOT_FOUND",
                () -> fixture.api().getBinding("f".repeat(64)));
        expectProblem(404, "RISK_METHOD_SELECTION_ACTIVATION_NOT_FOUND",
                () -> fixture.api().execute(9, "e".repeat(64), INPUT_SHA));

        RbvmRiskMethodSelectionPolicyActivationEvent cleared =
                RbvmRiskMethodSelectionPolicyActivationEvent.clear(
                        10,
                        "execution-api-test",
                        "",
                        Instant.parse("2026-08-23T08:00:10Z")
                );
        Fixture clearedFixture = fixture(policy, cleared, "4".repeat(64));
        expectProblem(409, "RISK_METHOD_SELECTION_ACTIVATION_CLEARED",
                () -> clearedFixture.api().execute(10, cleared.eventSha256(), INPUT_SHA));
        assert clearedFixture.results().calls == 0;
    }

    private static Fixture fixture(
            RbvmRiskMethodSelectionPolicy policy,
            RbvmRiskMethodSelectionPolicyActivationEvent activation,
            String resultSha
    ) {
        MemoryPolicyStore policies = new MemoryPolicyStore(policy);
        ExactActivationStore activations = new ExactActivationStore(activation);
        CountingResultMaterializer results = new CountingResultMaterializer(resultSha);
        MemoryBindingStore bindings = new MemoryBindingStore();
        DefaultActiveRiskMethodExecutionBindingMaterializer materializer =
                new DefaultActiveRiskMethodExecutionBindingMaterializer(
                        policies,
                        activations,
                        results,
                        bindings
                );
        return new Fixture(new ActiveRiskMethodExecutionApi(bindings, materializer), results);
    }

    private static RbvmRiskMethodSelectionPolicyActivationEvent active(
            int activationRevision,
            RbvmRiskMethodSelectionPolicy policy
    ) {
        return RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                activationRevision,
                policy,
                "execution-api-test",
                "",
                Instant.parse("2026-08-23T08:00:00Z").plusSeconds(activationRevision)
        );
    }

    private static void expectProblem(int status, String code, ThrowingAction action)
            throws Exception {
        boolean rejected = false;
        try {
            action.run();
        } catch (ActiveRiskMethodExecutionApi.ApiProblem problem) {
            rejected = problem.status() == status && problem.code().equals(code);
        }
        assert rejected : "expected API problem " + status + " " + code;
    }

    private record Fixture(
            ActiveRiskMethodExecutionApi api,
            CountingResultMaterializer results
    ) {
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }

    private static final class MemoryPolicyStore implements RiskMethodSelectionPolicyStore {
        private final RbvmRiskMethodSelectionPolicy policy;

        private MemoryPolicyStore(RbvmRiskMethodSelectionPolicy policy) {
            this.policy = policy;
        }

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
                int activationRevision
        ) {
            return activation.activationRevision() == activationRevision
                    ? Optional.of(activation) : Optional.empty();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByEventSha256(
                String eventSha256
        ) {
            return activation.eventSha256().equals(eventSha256)
                    ? Optional.of(activation) : Optional.empty();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> current() {
            throw new AssertionError("execution API must never resolve current activation");
        }
    }

    private static final class CountingResultMaterializer
            implements ActiveRiskMethodResultMaterializer {
        private final String resultSha;
        private int calls;

        private CountingResultMaterializer(String resultSha) {
            this.resultSha = resultSha;
        }

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
            String key = binding.activationEventSha256() + ":" + binding.inputSnapshotSha256();
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
            return Optional.ofNullable(byExecution.get(
                    activationEventSha256 + ":" + inputSnapshotSha256
            ));
        }
    }
}
