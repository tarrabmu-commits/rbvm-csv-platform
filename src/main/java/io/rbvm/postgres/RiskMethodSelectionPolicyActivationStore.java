package io.rbvm.postgres;

import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;

import java.io.IOException;
import java.util.Optional;

/** Append-only exact-identity persistence contract for explicit risk-method policy activation. */
public interface RiskMethodSelectionPolicyActivationStore {
    RiskMethodSelectionPolicyActivationInstallResult install(
            RbvmRiskMethodSelectionPolicyActivationEvent event
    ) throws IOException;

    Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByActivationRevision(
            int activationRevision
    ) throws IOException;

    Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByEventSha256(
            String eventSha256
    ) throws IOException;

    /** Current is defined only by the greatest explicit activation revision. */
    Optional<RbvmRiskMethodSelectionPolicyActivationEvent> current() throws IOException;
}
