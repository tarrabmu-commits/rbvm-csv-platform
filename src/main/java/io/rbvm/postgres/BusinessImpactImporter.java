package io.rbvm.postgres;

import java.io.IOException;
import java.nio.file.Path;

/** Persistence boundary for canonical BUSINESS_IMPACT_CSV_V1 evidence. */
@FunctionalInterface
public interface BusinessImpactImporter {
    BusinessImpactImportResult importFile(Path path) throws IOException;
}
