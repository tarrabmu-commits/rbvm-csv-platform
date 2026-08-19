package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionMethodologyPolicy;

import java.io.IOException;
import java.util.Optional;

/** Immutable persistence boundary for versioned RBVM decision methodology policies. */
public interface DecisionMethodologyPolicyStore {
    DecisionMethodologyPolicyInstallResult install(RbvmDecisionMethodologyPolicy policy)
            throws IOException;

    Optional<RbvmDecisionMethodologyPolicy> findByRevision(int revision) throws IOException;
}
