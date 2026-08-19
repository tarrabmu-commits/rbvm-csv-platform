package io.rbvm.postgres;

import java.io.IOException;
import java.nio.file.Path;

/** Persistence boundary for canonical EPSS_CSV_V1 evidence. */
@FunctionalInterface
public interface EpssImporter {
    EpssImportResult importFile(Path path) throws IOException;
}
