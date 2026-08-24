package io.rbvm.postgres;

import io.rbvm.csv.CsvFirstLocalIntelligenceSnapshotExporter;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Runtime factory for CSV-first V30 local public-intelligence lookup. */
public final class CsvFirstLocalIntelligenceRuntimeFactory {
    private CsvFirstLocalIntelligenceRuntimeFactory() {
    }

    public static Optional<CsvFirstLocalIntelligenceSnapshotExporter> fromEnvironment(
            Map<String, String> environment
    ) throws IOException {
        Objects.requireNonNull(environment, "environment");
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) return Optional.empty();

        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        PostgresPublicIntelligenceStore store = new PostgresPublicIntelligenceStore(connections, false);
        PostgresPublicIntelligenceSyncJobStore status =
                new PostgresPublicIntelligenceSyncJobStore(connections, false);
        return Optional.of(new PostgresCsvFirstLocalIntelligenceSnapshotExporter(store, status));
    }
}
