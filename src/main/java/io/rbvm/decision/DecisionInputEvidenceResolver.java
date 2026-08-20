package io.rbvm.decision;

import java.io.IOException;

/** Resolves exactly the immutable native evidence rows referenced by one Decision Input Snapshot. */
@FunctionalInterface
public interface DecisionInputEvidenceResolver {
    RbvmResolvedDecisionInput resolve(RbvmDecisionInputSnapshot snapshot) throws IOException;
}
