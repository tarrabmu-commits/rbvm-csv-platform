package io.rbvm.postgres;

import io.rbvm.decision.DecisionInputEvidenceResolver;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Discovers replay-verified Formula/Decision Input workflow capabilities from PostgreSQL V23+. */
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

        PostgresDecisionMethodologyPolicyStore methodologies =
                new PostgresDecisionMethodologyPolicyStore(connections, false);
        PostgresDecisionInputSnapshotStore snapshots = new PostgresDecisionInputSnapshotStore(
                connections,
                false
        );
        PostgresDecisionInputSnapshotBuilder snapshotBuilder =
                new PostgresDecisionInputSnapshotBuilder(
                        connections,
                        methodologies,
                        installedVersion
                );
        DecisionInputSnapshotMaterializer decisionInputMaterializer =
                new DefaultDecisionInputSnapshotMaterializer(snapshotBuilder, snapshots);
        DecisionInputRuntimeAccess decisionInputs = new DecisionInputRuntimeAccess(
                methodologies,
                snapshots,
                decisionInputMaterializer,
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
        );

        FormulaResultStore results = new PostgresFormulaResultStore(connections, false);
        DecisionInputEvidenceResolver evidenceResolver =
                new PostgresDecisionInputEvidenceResolver(connections, installedVersion);
        FormulaResultReplayVerifier replayVerifier = new FormulaResultReplayVerifier(
                results,
                snapshots,
                evidenceResolver,
                decisionInputs
        );
        FormulaResultMaterializer materializer = new DefaultFormulaResultMaterializer(
                snapshots,
                evidenceResolver,
                results,
                replayVerifier
        );
        return Optional.of(new Runtime(
                results,
                replayVerifier,
                materializer,
                decisionInputs
        ));
    }

    public record Runtime(
            FormulaResultStore results,
            FormulaResultReplayVerifier replayVerifier,
            FormulaResultMaterializer materializer,
            DecisionInputRuntimeAccess decisionInputs
    ) {
        public Runtime {
            results = Objects.requireNonNull(results, "results");
            replayVerifier = Objects.requireNonNull(replayVerifier, "replayVerifier");
            materializer = Objects.requireNonNull(materializer, "materializer");
            decisionInputs = Objects.requireNonNull(decisionInputs, "decisionInputs");
        }
    }
}
