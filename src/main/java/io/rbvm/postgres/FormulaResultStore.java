package io.rbvm.postgres;

import io.rbvm.decision.RbvmFormulaV1Explanation;

import java.io.IOException;
import java.util.Optional;

/** Append-only persistence boundary for exact Formula result/explanation identities. */
public interface FormulaResultStore {
    FormulaResultInstallResult install(RbvmFormulaV1Explanation explanation) throws IOException;

    Optional<StoredFormulaResult> findByExplanationSha256(String explanationSha256)
            throws IOException;

    Optional<StoredFormulaResult> findBySnapshotAndFormula(
            String inputSnapshotSha256,
            String formulaSha256
    ) throws IOException;
}
