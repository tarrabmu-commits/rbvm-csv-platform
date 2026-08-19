package io.rbvm.postgres;

import java.io.IOException;
import java.nio.file.Path;

/** Runtime boundary for importing APPLICABILITY_CSV_V1 evidence. */
@FunctionalInterface
public interface ApplicabilityImporter {
    ApplicabilityImportResult importFile(Path path) throws IOException;
}
