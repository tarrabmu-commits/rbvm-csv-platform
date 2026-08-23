package io.rbvm.postgres;

import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding;

import java.util.Objects;

/** Installed or replayed exact execution provenance binding. */
public record ActiveRiskMethodExecutionBindingMaterializationResult(
        RbvmActiveRiskMethodExecutionBinding binding,
        ActiveRiskMethodExecutionBindingInstallResult installResult
) {
    public ActiveRiskMethodExecutionBindingMaterializationResult {
        binding = Objects.requireNonNull(binding, "binding");
        installResult = Objects.requireNonNull(installResult, "installResult");
        if (installResult.status()
                == ActiveRiskMethodExecutionBindingInstallResult.Status.EXECUTION_CONFLICT) {
            throw new IllegalArgumentException(
                    "materialization result cannot contain a conflicting execution binding install"
            );
        }
        if (!binding.bindingSha256().equals(installResult.requestedBindingSha256())
                || !binding.bindingSha256().equals(installResult.observedBindingSha256())) {
            throw new IllegalArgumentException(
                    "materialization result binding identity must match installed/replayed identity"
            );
        }
    }

    public boolean replayed() {
        return installResult.status()
                == ActiveRiskMethodExecutionBindingInstallResult.Status.REPLAYED;
    }
}
