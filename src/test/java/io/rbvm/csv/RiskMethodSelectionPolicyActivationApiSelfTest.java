package io.rbvm.csv;

import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;
import io.rbvm.postgres.RiskMethodSelectionPolicyActivationInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyActivationStore;
import io.rbvm.postgres.RiskMethodSelectionPolicyInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyStore;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

public final class RiskMethodSelectionPolicyActivationApiSelfTest {
    private RiskMethodSelectionPolicyActivationApiSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        activatesReadsReplaysAndClearsExactPolicy();
        distinguishesNeverActivatedFromCleared();
        rejectsMissingConflictAndStaleIdentities();
        protectsV25PolicyRuntimeWithoutV26Activation();
        System.out.println("RiskMethodSelectionPolicyActivationApiSelfTest: PASS");
    }

    private static void activatesReadsReplaysAndClearsExactPolicy() throws Exception {
        CombinedStore store = new CombinedStore(true);
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        RiskMethodSelectionPolicyApi.Response policyInstall = api.install(
                1,
                "RBVM_FORMULA",
                RbvmFormulaV1.FORMULA_ID,
                RbvmFormulaV1.FORMULA_VERSION,
                RbvmFormulaV1.FORMULA_SHA256
        );
        String policySha = ((Map<?, ?>) policyInstall.body().get("policy"))
                .get("policySha256").toString();
        Instant firstAt = Instant.parse("2026-08-23T05:00:00Z");

        RiskMethodSelectionPolicyApi.Response inserted =
                api.activate(1, 1, policySha, "operator-1", firstAt);
        assert inserted.status() == 201;
        assert inserted.body().get("contractId")
                .equals(RiskMethodSelectionPolicyApi.ACTIVATION_INSTALLATION_CONTRACT_ID);
        assert inserted.body().get("installationStatus").equals("INSERTED");
        assert inserted.body().get("activationSemantics")
                .equals(RiskMethodSelectionPolicyApi.ACTIVATION_SELECTION_SEMANTICS);
        Map<?, ?> activation = (Map<?, ?>) inserted.body().get("activation");
        assert activation.get("activationState").equals("ACTIVE");
        assert activation.get("activationRevision").equals(1);
        assert activation.get("policyRevision").equals(1);
        assert activation.get("policySha256").equals(policySha);
        assert activation.get("changedBy").equals("operator-1");
        assert activation.get("recordedAt").equals(firstAt.toString());
        String eventSha = activation.get("eventSha256").toString();
        assert inserted.headers().get("Location").equals(
                "/api/v1/risk-method-selection-policy-activations/1/" + eventSha
        );
        assert inserted.headers().get("ETag").equals(
                "\"risk-method-selection-policy-activation-" + eventSha + "\""
        );

        RiskMethodSelectionPolicyApi.Response replay =
                api.activate(1, 1, policySha, "operator-1", firstAt);
        assert replay.status() == 200;
        assert replay.body().get("installationStatus").equals("REPLAYED");

        RiskMethodSelectionPolicyApi.Response current = api.currentActivation();
        assert current.status() == 200;
        assert ((Map<?, ?>) current.body().get("activation")).get("eventSha256").equals(eventSha);
        assert api.getActivation(1, eventSha).status() == 200;

        Instant clearAt = Instant.parse("2026-08-23T05:01:00Z");
        RiskMethodSelectionPolicyApi.Response cleared =
                api.clearActivation(2, "operator-1", clearAt);
        assert cleared.status() == 201;
        Map<?, ?> clearedEvent = (Map<?, ?>) cleared.body().get("activation");
        assert clearedEvent.get("activationState").equals("CLEARED");
        assert clearedEvent.get("policyRevision") == null;
        assert clearedEvent.get("policySha256") == null;
        Map<?, ?> currentCleared = (Map<?, ?>) api.currentActivation().body().get("activation");
        assert currentCleared.get("activationRevision").equals(2);
        assert currentCleared.get("activationState").equals("CLEARED");
    }

    private static void distinguishesNeverActivatedFromCleared() throws Exception {
        CombinedStore store = new CombinedStore(true);
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        expectProblem(404, "RISK_METHOD_SELECTION_POLICY_ACTIVATION_NOT_FOUND",
                api::currentActivation);
        api.clearActivation(1, "operator-2", Instant.parse("2026-08-23T06:00:00Z"));
        assert ((Map<?, ?>) api.currentActivation().body().get("activation"))
                .get("activationState").equals("CLEARED");
    }

    private static void rejectsMissingConflictAndStaleIdentities() throws Exception {
        CombinedStore store = new CombinedStore(true);
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        expectProblem(
                404,
                "RISK_METHOD_SELECTION_POLICY_NOT_FOUND",
                () -> api.activate(
                        1, 1, "0".repeat(64), "operator-3",
                        Instant.parse("2026-08-23T07:00:00Z")
                )
        );

        RiskMethodSelectionPolicyApi.Response policyInstall = api.install(
                1,
                "RBVM_FORMULA",
                RbvmFormulaV1.FORMULA_ID,
                RbvmFormulaV1.FORMULA_VERSION,
                RbvmFormulaV1.FORMULA_SHA256
        );
        String policySha = ((Map<?, ?>) policyInstall.body().get("policy"))
                .get("policySha256").toString();
        api.activate(5, 1, policySha, "operator-3", Instant.parse("2026-08-23T07:01:00Z"));

        expectProblem(
                409,
                "RISK_METHOD_SELECTION_POLICY_ACTIVATION_REVISION_CONFLICT",
                () -> api.clearActivation(
                        5, "operator-3", Instant.parse("2026-08-23T07:02:00Z")
                )
        );
        expectProblem(
                409,
                "STALE_RISK_METHOD_SELECTION_POLICY_ACTIVATION_REVISION",
                () -> api.clearActivation(
                        4, "operator-3", Instant.parse("2026-08-23T07:03:00Z")
                )
        );
        expectProblem(
                404,
                "RISK_METHOD_SELECTION_POLICY_ACTIVATION_NOT_FOUND",
                () -> api.getActivation(5, "0".repeat(64))
        );
    }

    private static void protectsV25PolicyRuntimeWithoutV26Activation() throws Exception {
        CombinedStore store = new CombinedStore(false);
        RiskMethodSelectionPolicyApi api = new RiskMethodSelectionPolicyApi(store);
        api.install(
                1,
                "RBVM_FORMULA",
                RbvmFormulaV1.FORMULA_ID,
                RbvmFormulaV1.FORMULA_VERSION,
                RbvmFormulaV1.FORMULA_SHA256
        );
        expectProblem(
                503,
                "RISK_METHOD_SELECTION_POLICY_ACTIVATION_PERSISTENCE_UNAVAILABLE",
                api::currentActivation
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
            RbvmRiskMethodSelectionPolicyActivationEvent same =
                    byRevision.get(event.activationRevision());
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
                    java.util.Comparator.comparingInt(
                            RbvmRiskMethodSelectionPolicyActivationEvent::activationRevision
                    )
            );
        }
    }
}
