package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

/** Builds one Finding-scoped, methodology-bound Decision Input Snapshot from native evidence. */
@FunctionalInterface
public interface DecisionInputSnapshotBuilder {
    RbvmDecisionInputSnapshot build(
            UUID findingId,
            int methodologyRevision,
            String methodologyPolicySha256,
            Instant evaluatedAt
    ) throws IOException;

    /** Exact requested Finding identity does not exist in the canonical projection. */
    final class FindingNotFoundException extends IOException {
        private static final long serialVersionUID = 1L;

        public FindingNotFoundException() {
            super("Decision input builder Finding_ID does not resolve to an existing canonical finding");
        }
    }
}
