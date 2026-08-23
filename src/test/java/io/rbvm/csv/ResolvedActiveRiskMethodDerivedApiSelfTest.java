package io.rbvm.csv;

import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;
import io.rbvm.postgres.RiskMethodSelectionPolicyActivationInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyActivationStore;
import io.rbvm.postgres.RiskMethodSelectionPolicyInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyStore;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/** Proof that resolved selection preserves every exact standard-derived methodology identity. */
public final class ResolvedActiveRiskMethodDerivedApiSelfTest {
    private ResolvedActiveRiskMethodDerivedApiSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        for (RbvmDerivedRiskMethodology.Definition definition
                : RbvmDerivedRiskMethodologyCatalog.definitions()) {
            RbvmRiskMethodSelectionPolicy policy =
                    RbvmRiskMethodSelectionPolicy.derived(1, definition);
            RbvmRiskMethodSelectionPolicyActivationEvent event =
                    RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                            1,
                            policy,
                            "derived-resolver-test",
                            "",
                            Instant.parse("2026-08-23T09:30:00Z")
                    );
            RiskMethodSelectionPolicyApi api =
                    new RiskMethodSelectionPolicyApi(new FixedStore(policy, event));

            RiskMethodSelectionPolicyApi.Response resolved = api.resolvedCurrentSelection();
            assert resolved.status() == 200;
            assert resolved.body().get("selectionState").equals("ACTIVE");
            Map<?, ?> selectedMethod = (Map<?, ?>) resolved.body().get("selectedMethod");
            assert selectedMethod.get("selectionRole").equals("PRIMARY");
            assert selectedMethod.get("methodFamily").equals("STANDARD_DERIVED");
            assert selectedMethod.get("methodId").equals(definition.methodologyId());
            assert selectedMethod.get("methodVersion").equals(definition.version());
            assert selectedMethod.get("methodSha256").equals(definition.methodologySha256());
        }
        System.out.println("ResolvedActiveRiskMethodDerivedApiSelfTest: PASS");
    }

    private static final class FixedStore implements RiskMethodSelectionPolicyStore {
        private final RbvmRiskMethodSelectionPolicy policy;
        private final RiskMethodSelectionPolicyActivationStore activationStore;

        private FixedStore(
                RbvmRiskMethodSelectionPolicy policy,
                RbvmRiskMethodSelectionPolicyActivationEvent event
        ) {
            this.policy = policy;
            this.activationStore = new FixedActivationStore(event);
        }

        @Override
        public RiskMethodSelectionPolicyInstallResult install(RbvmRiskMethodSelectionPolicy ignored) {
            throw new UnsupportedOperationException("read-only test store");
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByRevision(int revision) {
            return revision == policy.revision() ? Optional.of(policy) : Optional.empty();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByPolicySha256(String policySha256) {
            return policy.policySha256().equals(policySha256) ? Optional.of(policy) : Optional.empty();
        }

        @Override
        public Optional<RiskMethodSelectionPolicyActivationStore> activationStore() {
            return Optional.of(activationStore);
        }
    }

    private static final class FixedActivationStore implements RiskMethodSelectionPolicyActivationStore {
        private final RbvmRiskMethodSelectionPolicyActivationEvent event;

        private FixedActivationStore(RbvmRiskMethodSelectionPolicyActivationEvent event) {
            this.event = event;
        }

        @Override
        public RiskMethodSelectionPolicyActivationInstallResult install(
                RbvmRiskMethodSelectionPolicyActivationEvent ignored
        ) {
            throw new UnsupportedOperationException("read-only test store");
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByActivationRevision(
                int activationRevision
        ) {
            return activationRevision == event.activationRevision()
                    ? Optional.of(event)
                    : Optional.empty();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByEventSha256(
                String eventSha256
        ) {
            return event.eventSha256().equals(eventSha256) ? Optional.of(event) : Optional.empty();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> current() {
            return Optional.of(event);
        }
    }
}
