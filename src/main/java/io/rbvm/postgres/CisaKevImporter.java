package io.rbvm.postgres;

import java.io.IOException;
import java.nio.file.Path;

/** Transactional persistence boundary for CISA_KEV_CSV_V1. */
public interface CisaKevImporter {
    CisaKevImportResult importFile(Path path) throws IOException;
}
