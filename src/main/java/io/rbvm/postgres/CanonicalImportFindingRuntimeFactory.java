package io.rbvm.postgres;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

/** Builds the exact import-scoped Finding manifest capability when PostgreSQL is available. */
public final class CanonicalImportFindingRuntimeFactory {
    private CanonicalImportFindingRuntimeFactory() {
    }

    public static Optional<CanonicalImportFindingExporter> fromEnvironment(
            Map<String, String> environment
    ) throws IOException {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) return Optional.empty();
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        PostgresMigrator migrator = new PostgresMigrator(connections);
        int installedVersion = settings.migrate() ? migrator.migrate() : migrator.installedVersion();
        if (installedVersion < 1) return Optional.empty();
        return Optional.of(new PostgresCanonicalImportFindingExporter(connections));
    }
}
