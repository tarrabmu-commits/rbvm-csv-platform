package io.rbvm.postgres;

import io.rbvm.decision.RbvmDerivedRiskCanonicalResult;

import java.io.IOException;
import java.util.Optional;

/** Append-only persistence boundary for exact canonical derived-risk results. */
public interface DerivedRiskResultStore {
    DerivedRiskResultInstallResult install(RbvmDerivedRiskCanonicalResult result) throws IOException;

    Optional<StoredDerivedRiskResult> findByResultSha256(String resultSha256) throws IOException;

    Optional<StoredDerivedRiskResult> findBySnapshotAndMethodology(
            String inputSnapshotSha256,
            String methodologyId,
            String methodologySha256
    ) throws IOException;
}
