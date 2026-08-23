package io.rbvm.csv;

import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;
import io.rbvm.postgres.RiskMethodSelectionPolicyActivationInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyActivationStore;
import io.rbvm.postgres.RiskMethodSelectionPolicyInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyStore;

import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** Contract proof for resolving explicit activation to one exact persisted risk-method identity. */
public final class ResolvedActiveRiskMethodApiSelfTest {
    private ResolvedActiveRiskMethodApiSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        resolvesActiveSelectionByCurrentAndExactActivationIdentity();
        preservesNeverActivatedAndClearedAsDifferentStates();
        failsClosedWhenActivePolicyIdentityCannotBeResolved();
        protectsV25RuntimeWithoutV26ActivationCapability();
        System.out.println("ResolvedActiveRiskMethodApiSelfTest: PASS");
    }

    private static void resolvesActiveSelectionByCurrentAndExactActivationIdentity()
            throws Exception {
        CombinedStore store = new CombinedStore(true);
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        RiskMethodSelectionPolicyApi.Response installed = api.install(
                1,
                "RBVM_FORMULA",
                RbvmFormulaV1.FORMULA_ID,
                RbvmFormulaV1.FORMULA_VERSION,
                RbvmFormulaV1.FORMULA_SHA256
        );
        Map<?, ?> policy = (Map<?, ?>) installed.body().get("policy");
        String policySha = policy.get("policySha256").toString();
        RiskMethodSelectionPolicyApi.Response activated = api.activate(
                7,
                1,
                policySha,
                "resolver-operator",
                Instant.parse("2026-08-23T08:00:00Z")
        );
        Map<?, ?> activation = (Map<?, ?>) activated.body().get("activation");
        String eventSha = activation.get("eventSha256").toString();

        RiskMethodSelectionPolicyApi.Response current = api.resolvedCurrentSelection();
        assert current.status() == 200;
        assert current.body().get("contractId")
                .equals(RiskMethodSelectionPolicyApi.RESOLVED_ACTIVE_METHOD_CONTRACT_ID);
        assert current.body().get("resolutionSemantics")
                .equals(RiskMethodSelectionPolicyApi.RESOLVED_ACTIVE_METHOD_SEMANTICS);
        assert current.body().get("selectionState").equals("ACTIVE");
        Map<?, ?> currentActivation = (Map<?, ?>) current.body().get("activation");
        assert currentActivation.get("activationRevision").equals(7);
        assert currentActivation.get("eventSha256").equals(eventSha);
        Map<?, ?> currentPolicy = (Map<?, ?>) current.body().get("policy");
        assert currentPolicy.get("revision").equals(1);
        assert currentPolicy.get("policySha256").equals(policySha);
        Map<?, ?> method = (Map<?, ?>) current.body().get("selectedMethod");
        assert method.get("selectionRole").equals("PRIMARY");
        assert method.get("methodFamily").equals("RBVM_FORMULA");
        assert method.get("methodId").equals(RbvmFormulaV1.FORMULA_ID);
        assert method.get("methodVersion").equals(RbvmFormulaV1.FORMULA_VERSION);
        assert method.get("methodSha256").equals(RbvmFormulaV1.FORMULA_SHA256);
        assert current.headers().get("ETag").equals(
                "\"risk-method-selection-policy-activation-" + eventSha + "\""
        );
        assert current.headers().get("Location").equals(
                "/api/v1/risk-method-selection-policy-activations/7/" + eventSha + "/resolved"
        );

        RiskMethodSelectionPolicyApi.Response exact = api.resolvedActivation(7, eventSha);
        assert exact.body().equals(current.body());
        assert exact.headers().equals(current.headers());
        expectProblem(
                404,
                "RISK_METHOD_SELECTION_POLICY_ACTIVATION_NOT_FOUND",
                () -> api.resolvedActivation(7, "0".repeat(64))
        );
    }

    private static void preservesNeverActivatedAndClearedAsDifferentStates() throws Exception {
        CombinedStore store = new CombinedStore(true);
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        expectProblem(
                404,
                "RISK_METHOD_SELECTION_POLICY_ACTIVATION_NOT_FOUND",
                api::resolvedCurrentSelection
        );

        RiskMethodSelectionPolicyApi.Response cleared = api.clearActivation(
                1,
                "resolver-operator",
                Instant.parse("2026-08-23T08:05:00Z")
        );
        String eventSha = ((Map<?, ?>) cleared.body().get("activation"))
                .get("eventSha256").toString();
        RiskMethodSelectionPolicyApi.Response resolved = api.resolvedCurrentSelection();
        assert resolved.status() == 200;
        assert resolved.body().get("selectionState").equals("CLEARED");
        assert resolved.body().get("policy") == null;
        assert resolved.body().get("selectedMethod") == null;
        Map<?, ?> activation = (Map<?, ?>) resolved.body().get("activation");
        assert activation.get("activationState").equals("CLEARED");
        assert activation.get("policyRevision") == null;
        assert activation.get("policySha256") == null;
        assert api.resolvedActivation(1, eventSha).body().equals(resolved.body());
    }

    private static void failsClosedWhenActivePolicyIdentityCannotBeResolved() throws Exception {
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
        api.activate(
                1,
                1,
                policySha,
                "resolver-operator",
                Instant.parse("2026-08-23T08:10:00Z")
        );
        store.policies.remove(1);
        expectProblem(
                500,
                "RISK_METHOD_SELECTION_POLICY_ACTIVATION_INTEGRITY_FAILURE",
                api::resolvedCurrentSelection
        );
    }

    private static void protectsV25RuntimeWithoutV26ActivationCapability() throws Exception {
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(new CombinedStore(false));
        expectProblem(
                503,
                "RISK_METHOD_SELECTION_POLICY_ACTIVATION_PERSISTENCE_UNAVAILABLE",
                api::resolvedCurrentSelection
        );
    }

    private static void expectProblem(int status, String code, ThrowingAction action)
            throws Exception {
        boolean rejected = false;
        try {
            action.run();
        } catch (RiskMethodSelectionPolicyApi.ApiProblem problem) {
            rejected = problem.status() == status && problem.code().equals(code);
        }
        assert rejected : "expected API problem " + status + " " + code;
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
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
