package io.rbvm.postgres;

import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;

import java.io.IOException;
import java.util.Optional;

/** Immutable persistence boundary for exact primary risk-method selection policy revisions. */
public interface RiskMethodSelectionPolicyStore {
    RiskMethodSelectionPolicyInstallResult install(RbvmRiskMethodSelectionPolicy policy)
            throws IOException;

    Optional<RbvmRiskMethodSelectionPolicy> findByRevision(int revision) throws IOException;

    Optional<RbvmRiskMethodSelectionPolicy> findByPolicySha256(String policySha256)
            throws IOException;
}
