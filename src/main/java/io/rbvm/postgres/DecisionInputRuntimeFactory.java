package io.rbvm.postgres;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Discovers the explicit Decision Input operator/read workflow independently from Formula replay.
 *
 * <p>The workflow is intentionally V23-gated while Formula Result transport is being completed,
 * but its builder/materializer remain outside FormulaResultRuntimeFactory so Formula replay cannot
 * accidentally rebuild or re-select Decision Input evidence.</p>
 */
public final class DecisionInputRuntimeFactory {
    private static final int REQUIRED_SCHEMA_VERSION = 23;

    private DecisionInputRuntimeFactory() {
    }

    public static Optional<DecisionInputRuntimeAccess> fromEnvironment(
            Map<String, String> environment
    ) throws IOException {
        Objects.requireNonNull(environment, "environment");
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) {
            return Optional.empty();
        }

        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        PostgresMigrator migrator = new PostgresMigrator(connections);
        int installedVersion = settings.migrate() ? migrator.migrate() : migrator.installedVersion();
        if (installedVersion < REQUIRED_SCHEMA_VERSION) {
            return Optional.empty();
        }

        PostgresDecisionMethodologyPolicyStore methodologies =
                new PostgresDecisionMethodologyPolicyStore(connections, false);
        PostgresDecisionInputSnapshotStore snapshots =
                new PostgresDecisionInputSnapshotStore(connections, false);
        PostgresDecisionInputSnapshotBuilder builder =
                new PostgresDecisionInputSnapshotBuilder(
                        connections,
                        methodologies,
                        installedVersion
                );
        DecisionInputSnapshotMaterializer materializer =
                new DefaultDecisionInputSnapshotMaterializer(builder, snapshots);

        return Optional.of(new DecisionInputRuntimeAccess(
                methodologies,
                snapshots,
                materializer,
                new PostgresDecisionInputHistoryReader(
                        connections,
                        snapshots,
                        installedVersion
                ),
                new PostgresDecisionMethodologyCatalog(
                        connections,
                        methodologies,
                        installedVersion
                )
        ));
    }
}
