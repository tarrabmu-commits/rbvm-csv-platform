package io.rbvm.postgres;

import io.rbvm.csv.CanonicalProjection;
import io.rbvm.csv.NoopCanonicalProjection;

import java.io.IOException;
import java.util.Map;

public final class CanonicalProjectionFactory {
    private CanonicalProjectionFactory() {
    }

    public static CanonicalProjection fromEnvironment(Map<String, String> environment)
            throws IOException {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) {
            return new NoopCanonicalProjection();
        }
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        return new PostgresCanonicalProjection(connections, settings.migrate());
    }
}
