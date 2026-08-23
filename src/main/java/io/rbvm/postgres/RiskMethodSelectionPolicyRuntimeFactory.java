package io.rbvm.postgres;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Discovers exact risk-method selection policy capabilities from PostgreSQL V25+. */
public final class RiskMethodSelectionPolicyRuntimeFactory {
    private static final int REQUIRED_SCHEMA_VERSION = 25;

    private RiskMethodSelectionPolicyRuntimeFactory() {
    }

    public static Optional<Runtime> fromEnvironment(Map<String, String> environment)
            throws IOException {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) return Optional.empty();

        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        PostgresMigrator migrator = new PostgresMigrator(connections);
        int installedVersion = settings.migrate() ? migrator.migrate() : migrator.installedVersion();
        if (installedVersion < REQUIRED_SCHEMA_VERSION) return Optional.empty();

        return Optional.of(new Runtime(
                new PostgresRiskMethodSelectionPolicyStore(connections, false)
        ));
    }

    public record Runtime(RiskMethodSelectionPolicyStore policies) {
        public Runtime {
            policies = Objects.requireNonNull(policies, "policies");
        }
    }
}
