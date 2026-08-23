package io.rbvm.postgres;

import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;

import java.io.IOException;
import java.util.Objects;

/**
 * Resolves one exact historical activation identity, executes its exact selected method against one
 * exact Decision Input, and persists immutable execution provenance. No current/default selector is
 * accepted by this contract.
 */
public final class DefaultActiveRiskMethodExecutionBindingMaterializer {
    private final RiskMethodSelectionPolicyStore policies;
    private final ActiveRiskMethodResultMaterializer results;
    private final ActiveRiskMethodExecutionBindingStore bindings;

    public DefaultActiveRiskMethodExecutionBindingMaterializer(
            RiskMethodSelectionPolicyStore policies,
            ActiveRiskMethodResultMaterializer results,
            ActiveRiskMethodExecutionBindingStore bindings
    ) {
        this.policies = Objects.requireNonNull(policies, "policies");
        this.results = Objects.requireNonNull(results, "results");
        this.bindings = Objects.requireNonNull(bindings, "bindings");
    }

    public ActiveRiskMethodExecutionBindingMaterializationResult materialize(
            int activationRevision,
            String activationEventSha256,
            String inputSnapshotSha256
    ) throws IOException {
        if (activationRevision < 1) {
            throw new IllegalArgumentException("activationRevision must be positive");
        }
        requireSha(activationEventSha256, "activationEventSha256");
        requireSha(inputSnapshotSha256, "inputSnapshotSha256");

        RiskMethodSelectionPolicyActivationStore activationStore = policies.activationStore()
                .orElseThrow(ActivationPersistenceUnavailableException::new);
        RbvmRiskMethodSelectionPolicyActivationEvent activation = activationStore
                .findByActivationRevision(activationRevision)
                .filter(candidate -> candidate.eventSha256().equals(activationEventSha256))
                .orElseThrow(ActivationNotFoundException::new);
        if (!activation.activatesPolicy()) {
            throw new ExplicitlyClearedActivationException();
        }

        RbvmRiskMethodSelectionPolicy policy = policies.findByRevision(activation.policyRevision())
                .filter(candidate -> candidate.policySha256().equals(activation.policySha256()))
                .orElseThrow(PolicyIntegrityFailureException::new);

        RbvmActiveRiskMethodExecutionBinding existing = bindings.findByActivationAndInput(
                activationEventSha256,
                inputSnapshotSha256
        ).orElse(null);
        if (existing != null) {
            requireExistingBindingMatches(existing, activation, policy, inputSnapshotSha256);
            ActiveRiskMethodExecutionBindingInstallResult replay =
                    new ActiveRiskMethodExecutionBindingInstallResult(
                            ActiveRiskMethodExecutionBindingInstallResult.Status.REPLAYED,
                            existing.bindingSha256(),
                            existing.bindingSha256()
                    );
            return new ActiveRiskMethodExecutionBindingMaterializationResult(existing, replay);
        }

        try {
            policy.requireCatalogBound();
        } catch (IllegalArgumentException exception) {
            throw new SelectedMethodUnavailableException(exception);
        }

        ActiveRiskMethodNativeResult nativeResult = results.materialize(
                policy,
                inputSnapshotSha256
        );
        requireNativeResultMatches(nativeResult, policy, inputSnapshotSha256);

        RbvmActiveRiskMethodExecutionBinding binding =
                RbvmActiveRiskMethodExecutionBinding.bind(
                        activation,
                        policy,
                        inputSnapshotSha256,
                        nativeResult.resultFamily(),
                        nativeResult.resultSha256()
                );
        ActiveRiskMethodExecutionBindingInstallResult installed = bindings.install(binding);
        if (installed.status()
                == ActiveRiskMethodExecutionBindingInstallResult.Status.EXECUTION_CONFLICT) {
            throw new ExecutionBindingConflictException(
                    installed.observedBindingSha256()
            );
        }
        return new ActiveRiskMethodExecutionBindingMaterializationResult(binding, installed);
    }

    private static void requireExistingBindingMatches(
            RbvmActiveRiskMethodExecutionBinding existing,
            RbvmRiskMethodSelectionPolicyActivationEvent activation,
            RbvmRiskMethodSelectionPolicy policy,
            String inputSnapshotSha256
    ) {
        if (existing.activationRevision() != activation.activationRevision()
                || !existing.activationEventSha256().equals(activation.eventSha256())
                || existing.policyRevision() != policy.revision()
                || !existing.policySha256().equals(policy.policySha256())
                || existing.selectionRole() != policy.selectionRole()
                || existing.methodFamily() != policy.methodFamily()
                || !existing.methodId().equals(policy.methodId())
                || existing.methodVersion() != policy.methodVersion()
                || !existing.methodSha256().equals(policy.methodSha256())
                || !existing.inputSnapshotSha256().equals(inputSnapshotSha256)) {
            throw new ExecutionBindingIntegrityFailureException(
                    "Persisted execution binding does not match exact activation, policy, and input identities"
            );
        }
    }

    private static void requireNativeResultMatches(
            ActiveRiskMethodNativeResult nativeResult,
            RbvmRiskMethodSelectionPolicy policy,
            String inputSnapshotSha256
    ) {
        Objects.requireNonNull(nativeResult, "nativeResult");
        if (!nativeResult.inputSnapshotSha256().equals(inputSnapshotSha256)
                || nativeResult.methodFamily() != policy.methodFamily()
                || !nativeResult.methodId().equals(policy.methodId())
                || nativeResult.methodVersion() != policy.methodVersion()
                || !nativeResult.methodSha256().equals(policy.methodSha256())) {
            throw new ExecutionBindingIntegrityFailureException(
                    "Native result identity does not match the exact selected policy and Decision Input"
            );
        }
    }

    private static void requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }

    public static final class ActivationPersistenceUnavailableException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public ActivationPersistenceUnavailableException() {
            super("Risk Method Selection Policy activation persistence is unavailable");
        }
    }

    public static final class ActivationNotFoundException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public ActivationNotFoundException() {
            super("No activation event matches the exact activation revision and event SHA");
        }
    }

    public static final class ExplicitlyClearedActivationException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public ExplicitlyClearedActivationException() {
            super("The exact activation event explicitly clears the active risk method");
        }
    }

    public static final class PolicyIntegrityFailureException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public PolicyIntegrityFailureException() {
            super("ACTIVE activation references an exact policy identity that cannot be resolved");
        }
    }

    public static final class SelectedMethodUnavailableException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public SelectedMethodUnavailableException(Throwable cause) {
            super("The exact selected risk method is not executable in the current catalog", cause);
        }
    }

    public static final class ExecutionBindingIntegrityFailureException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public ExecutionBindingIntegrityFailureException(String message) {
            super(message);
        }
    }

    public static final class ExecutionBindingConflictException extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        private final String observedBindingSha256;

        public ExecutionBindingConflictException(String observedBindingSha256) {
            super("A different execution binding already exists for this exact activation and input");
            this.observedBindingSha256 = Objects.requireNonNull(
                    observedBindingSha256,
                    "observedBindingSha256"
            );
        }

        public String observedBindingSha256() {
            return observedBindingSha256;
        }
    }
}
