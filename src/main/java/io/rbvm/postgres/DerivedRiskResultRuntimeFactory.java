package io.rbvm.postgres;

import io.rbvm.decision.DecisionInputEvidenceResolver;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Discovers exact derived-risk result capabilities from PostgreSQL V24+. */
public final class DerivedRiskResultRuntimeFactory {
    private static final int REQUIRED_SCHEMA_VERSION = 24;

    private DerivedRiskResultRuntimeFactory() {
    }

    public static Optional<Runtime> fromEnvironment(Map<String, String> environment)
            throws IOException {
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

        DerivedRiskResultStore results = new PostgresDerivedRiskResultStore(connections, false);
        DecisionInputSnapshotStore snapshots = new PostgresDecisionInputSnapshotStore(
                connections,
                false
        );
        DecisionInputEvidenceResolver evidenceResolver =
                new PostgresDecisionInputEvidenceResolver(connections, installedVersion);
        DerivedRiskResultReplayVerifier replayVerifier = new DerivedRiskResultReplayVerifier(
                results,
                snapshots,
                evidenceResolver
        );
        DerivedRiskResultMaterializer materializer = new DefaultDerivedRiskResultMaterializer(
                snapshots,
                evidenceResolver,
                results,
                replayVerifier
        );
        return Optional.of(new Runtime(results, replayVerifier, materializer));
    }

    public record Runtime(
            DerivedRiskResultStore results,
            DerivedRiskResultReplayVerifier replayVerifier,
            DerivedRiskResultMaterializer materializer
    ) {
        public Runtime {
            results = Objects.requireNonNull(results, "results");
            replayVerifier = Objects.requireNonNull(replayVerifier, "replayVerifier");
            materializer = Objects.requireNonNull(materializer, "materializer");
        }
    }
}
