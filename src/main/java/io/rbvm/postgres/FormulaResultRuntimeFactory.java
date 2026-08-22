package io.rbvm.postgres;

import io.rbvm.decision.DecisionInputEvidenceResolver;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Discovers the replay-verified Formula Result read capability from PostgreSQL schema V23+. */
public final class FormulaResultRuntimeFactory {
    private static final int REQUIRED_SCHEMA_VERSION = 23;

    private FormulaResultRuntimeFactory() {
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

        FormulaResultStore results = new PostgresFormulaResultStore(connections, false);
        DecisionInputSnapshotStore snapshots = new PostgresDecisionInputSnapshotStore(
                connections,
                false
        );
        DecisionInputEvidenceResolver evidenceResolver =
                new PostgresDecisionInputEvidenceResolver(connections, installedVersion);
        FormulaResultReplayVerifier replayVerifier = new FormulaResultReplayVerifier(
                results,
                snapshots,
                evidenceResolver
        );
        return Optional.of(new Runtime(results, replayVerifier));
    }

    public record Runtime(
            FormulaResultStore results,
            FormulaResultReplayVerifier replayVerifier
    ) {
        public Runtime {
            results = Objects.requireNonNull(results, "results");
            replayVerifier = Objects.requireNonNull(replayVerifier, "replayVerifier");
        }
    }
}
