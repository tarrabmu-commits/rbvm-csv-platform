package io.rbvm.postgres;

import java.io.IOException;
import java.nio.file.Path;

/** Persistence boundary for canonical ASSET_CONTEXT_CSV_V1 evidence. */
@FunctionalInterface
public interface AssetContextImporter {
    AssetContextImportResult importFile(Path path) throws IOException;
}
