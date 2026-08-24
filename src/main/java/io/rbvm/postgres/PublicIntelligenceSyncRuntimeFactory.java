package io.rbvm.postgres;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Runtime factory for V31 public-intelligence synchronization lifecycle/status. */
public final class PublicIntelligenceSyncRuntimeFactory {
    private PublicIntelligenceSyncRuntimeFactory() {
    }

    public static Optional<PostgresPublicIntelligenceSyncJobStore> fromEnvironment(
            Map<String, String> environment
    ) throws IOException {
        Objects.requireNonNull(environment, "environment");
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) return Optional.empty();
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        // CanonicalProjectionFactory runs first in product startup and owns migration policy.
        // This capability therefore verifies schema availability without independently changing it.
        return Optional.of(new PostgresPublicIntelligenceSyncJobStore(connections, false));
    }
}
