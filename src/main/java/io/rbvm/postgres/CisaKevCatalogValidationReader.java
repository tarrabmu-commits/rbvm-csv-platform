package io.rbvm.postgres;

import java.io.IOException;
import java.util.UUID;

/**
 * Proves whether one successful CISA KEV V30 run completed through the validated V31 acquisition lifecycle.
 */
@FunctionalInterface
public interface CisaKevCatalogValidationReader {
    boolean isCompleteValidatedCatalog(UUID syncRunId) throws IOException;
}
