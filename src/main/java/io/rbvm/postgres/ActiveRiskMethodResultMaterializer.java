package io.rbvm.postgres;

import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;

import java.io.IOException;

/** Executes exactly the method selected by one exact Risk Method Selection Policy. */
@FunctionalInterface
public interface ActiveRiskMethodResultMaterializer {
    ActiveRiskMethodNativeResult materialize(
            RbvmRiskMethodSelectionPolicy policy,
            String inputSnapshotSha256
    ) throws IOException;
}
