package io.rbvm.postgres;

import java.io.IOException;
import java.nio.file.Path;

/** Runtime boundary for importing CVSS_V31_CSV_V1 technical-severity evidence. */
@FunctionalInterface
public interface CvssV31Importer {
    CvssV31ImportResult importFile(Path path) throws IOException;
}
