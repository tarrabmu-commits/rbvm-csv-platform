package io.rbvm.postgres;

import java.io.IOException;
import java.nio.file.Path;

/** Persistence boundary for canonical NETWORK_REACHABILITY_CSV_V1 evidence. */
@FunctionalInterface
public interface NetworkReachabilityImporter {
    NetworkReachabilityImportResult importFile(Path path) throws IOException;
}
