package io.rbvm.csv;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Exports the public-intelligence subset required by one uploaded CSV without performing
 * provider network I/O. Implementations must preserve missing provider evidence explicitly.
 */
public interface CsvFirstLocalIntelligenceSnapshotExporter {
    String CONTRACT_ID = "CSV_FIRST_LOCAL_PUBLIC_INTELLIGENCE_EXPORT_V1";

    record ExportSummary(
            long uniqueCves,
            long providerRecords,
            long cvesWithoutActiveProviderRecords,
            long providersWithSuccessfulSnapshot
    ) {
        public ExportSummary {
            if (uniqueCves < 0 || providerRecords < 0 || cvesWithoutActiveProviderRecords < 0
                    || providersWithSuccessfulSnapshot < 0) {
                throw new IllegalArgumentException("local intelligence export counts must be non-negative");
            }
        }
    }

    ExportSummary export(Path inputCsv, Path outputDirectory) throws IOException;
}
