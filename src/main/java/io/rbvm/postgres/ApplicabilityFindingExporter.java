package io.rbvm.postgres;

import java.io.IOException;

/** Exports tenant-scoped canonical Finding_ID references for applicability assessment work. */
@FunctionalInterface
public interface ApplicabilityFindingExporter {
    byte[] exportCsv() throws IOException;
}
