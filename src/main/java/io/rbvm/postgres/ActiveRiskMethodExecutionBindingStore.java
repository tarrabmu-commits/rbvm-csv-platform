package io.rbvm.postgres;

import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding;

import java.io.IOException;
import java.util.Optional;

/** Immutable persistence boundary for exact active risk-method execution provenance. */
public interface ActiveRiskMethodExecutionBindingStore {
    ActiveRiskMethodExecutionBindingInstallResult install(
            RbvmActiveRiskMethodExecutionBinding binding
    ) throws IOException;

    Optional<RbvmActiveRiskMethodExecutionBinding> findByBindingSha256(String bindingSha256)
            throws IOException;

    Optional<RbvmActiveRiskMethodExecutionBinding> findByActivationAndInput(
            String activationEventSha256,
            String inputSnapshotSha256
    ) throws IOException;
}
