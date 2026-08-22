package io.rbvm.postgres;

import java.io.IOException;

/** Materializes Formula V1 only from one exact already-persisted Decision Input V3 identity. */
@FunctionalInterface
public interface FormulaResultMaterializer {
    FormulaResultMaterializationResult materialize(String inputSnapshotSha256) throws IOException;
}
