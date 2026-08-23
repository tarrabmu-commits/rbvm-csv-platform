package io.rbvm.postgres;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

/** Exports the exact canonical Findings reached from one committed import's observation links. */
@FunctionalInterface
public interface CanonicalImportFindingExporter {
    Optional<byte[]> exportCsv(UUID importId) throws IOException;
}
