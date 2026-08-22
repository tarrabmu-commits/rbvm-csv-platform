package io.rbvm.postgres;

import java.io.IOException;

/** Materializes one exact derived methodology from one exact persisted Decision Input V3 identity. */
@FunctionalInterface
public interface DerivedRiskResultMaterializer {
    DerivedRiskResultMaterializationResult materialize(
            String inputSnapshotSha256,
            String methodologyId,
            String methodologySha256
    ) throws IOException;
}
