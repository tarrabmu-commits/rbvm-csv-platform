package io.rbvm.postgres;

import io.rbvm.csv.CanonicalProjection;
import io.rbvm.csv.NoopCanonicalProjection;
import io.rbvm.domain.DomainCatalog;
import io.rbvm.domain.InMemoryDomainCatalog;

import java.io.IOException;
import java.util.Map;

public final class CanonicalProjectionFactory {
    private CanonicalProjectionFactory() {
    }

    public static CanonicalProjection fromEnvironment(Map<String, String> environment)
            throws IOException {
        return runtimeFromEnvironment(environment).canonicalProjection();
    }

    public static RuntimeComponents runtimeFromEnvironment(Map<String, String> environment)
            throws IOException {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) {
            return new RuntimeComponents(
                    new NoopCanonicalProjection(),
                    new InMemoryDomainCatalog()
            );
        }
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        return new RuntimeComponents(
                new PostgresCanonicalProjection(connections, settings.migrate()),
                new PostgresReadCatalog(connections)
        );
    }

    public record RuntimeComponents(
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog
    ) {
    }
}
