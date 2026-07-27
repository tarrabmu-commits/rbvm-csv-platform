package io.rbvm.postgres;

import io.rbvm.csv.JsonOutput;

import java.util.Map;

/** Connects, migrates when configured, and prints a credential-safe projection health result. */
public final class PostgresProjectionCheck {
    private PostgresProjectionCheck() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(
                System.getenv()
        );
        if (!settings.enabled()) {
            throw new IllegalArgumentException(
                    "Set RBVM_PROJECTION_BACKEND=POSTGRESQL before running this check");
        }
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        try (PostgresCanonicalProjection projection = new PostgresCanonicalProjection(
                connections,
                settings.migrate()
        )) {
            Map<String, Object> health = projection.health();
            System.out.print(JsonOutput.pretty(health));
            if (!"UP".equals(health.get("status"))) {
                throw new IllegalStateException("PostgreSQL projection preflight is not UP");
            }
        }
    }
}
