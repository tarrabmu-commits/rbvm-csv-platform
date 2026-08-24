package io.rbvm.postgres;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

/** Builds canonical MVP-priority persistence only when PostgreSQL V29 is available. */
public final class CanonicalMvpPriorityRuntimeFactory {
    private CanonicalMvpPriorityRuntimeFactory() {
    }

    public static Optional<CanonicalMvpPriorityStore> fromEnvironment(
            Map<String, String> environment
    ) throws IOException {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) return Optional.empty();
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        PostgresMigrator migrator = new PostgresMigrator(connections);
        int installedVersion = settings.migrate() ? migrator.migrate() : migrator.installedVersion();
        if (installedVersion < 29) return Optional.empty();
        return Optional.of(new PostgresCanonicalMvpPriorityStore(connections));
    }
}
