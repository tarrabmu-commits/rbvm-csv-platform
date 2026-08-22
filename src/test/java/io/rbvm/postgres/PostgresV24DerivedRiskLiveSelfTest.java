package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDerivedRiskCanonicalResult;
import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.decision.RbvmResolvedDecisionInput;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/** Live PostgreSQL coverage for V24 append-only derived-risk persistence and exact replay. */
public final class PostgresV24DerivedRiskLiveSelfTest {
    private PostgresV24DerivedRiskLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");

        JdbcConnectionFactory ownerConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        require(new PostgresMigrator(ownerConnections).installedVersion() == 24,
                "V24 derived-risk live test requires schema version 24");

        JdbcConnectionFactory runtimeConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                "rbvm_runtime",
                "rbvm-live-test"
        );
        String snapshotSha = latestV3SnapshotSha(runtimeConnections);
        PostgresDecisionInputSnapshotStore decisionInputs = new PostgresDecisionInputSnapshotStore(
                runtimeConnections,
                false
        );
        RbvmDecisionInputSnapshot snapshot = decisionInputs.findBySha256(snapshotSha).orElseThrow();
        require(snapshot.isV3(), "derived risk persistence requires Decision Input V3");

        PostgresDecisionInputEvidenceResolver resolver = new PostgresDecisionInputEvidenceResolver(
                runtimeConnections,
                24
        );
        RbvmResolvedDecisionInput resolved = resolver.resolve(snapshot);
        PostgresDerivedRiskResultStore results = new PostgresDerivedRiskResultStore(
                runtimeConnections,
                false
        );
        DerivedRiskResultReplayVerifier replayVerifier = new DerivedRiskResultReplayVerifier(
                results,
                decisionInputs,
                resolver
        );

        for (RbvmDerivedRiskMethodology.Definition definition
                : RbvmDerivedRiskMethodologyCatalog.definitions()) {
            RbvmDerivedRiskMethodology methodology = RbvmDerivedRiskMethodologyCatalog
                    .find(definition.methodologyId())
                    .orElseThrow();
            RbvmDerivedRiskCanonicalResult canonical = RbvmDerivedRiskCanonicalResult.from(
                    methodology.evaluate(resolved)
            );

            DerivedRiskResultInstallResult inserted = results.install(canonical);
            require(inserted.status() == DerivedRiskResultInstallResult.Status.INSERTED,
                    "first derived risk materialization must append one row");
            require(inserted.persistedResultSha256().equals(canonical.canonicalSha256()),
                    "insert must preserve canonical derived result identity");

            DerivedRiskResultInstallResult replayed = results.install(canonical);
            require(replayed.status() == DerivedRiskResultInstallResult.Status.REPLAYED,
                    "exact derived risk retry must replay without duplicate row");
            require(replayed.persistedResultSha256().equals(canonical.canonicalSha256()),
                    "replay must preserve canonical derived result identity");

            StoredDerivedRiskResult stored = results
                    .findByResultSha256(canonical.canonicalSha256())
                    .orElseThrow();
            require(stored.inputSnapshotSha256().equals(snapshot.snapshotSha256()),
                    "stored derived risk result must retain exact snapshot identity");
            require(stored.methodologyId().equals(definition.methodologyId()),
                    "stored derived risk result must retain methodology identity");
            require(stored.methodologySha256().equals(definition.methodologySha256()),
                    "stored derived risk result must retain methodology SHA identity");

            replayVerifier.verify(stored);
            replayVerifier.verifyBySnapshotAndMethodology(
                    snapshot.snapshotSha256(),
                    definition.methodologyId(),
                    definition.methodologySha256()
            );
        }

        require(derivedRiskRowCount(runtimeConnections) == 2,
                "V24 live fixture must persist exactly one result per implemented derived methodology");
        proveAppendOnly(runtimeConnections);

        System.out.println(
                "PostgresV24DerivedRiskLiveSelfTest: PASS schema=24 methodologies=2 "
                        + "insert=PASS replay=PASS exact_identity=PASS append_only=PASS"
        );
    }

    private static String latestV3SnapshotSha(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT snapshot_sha256
                     FROM rbvm.decision_input_snapshot
                     WHERE contract_id = 'RBVM_DECISION_INPUT_SNAPSHOT_V3'
                     ORDER BY persisted_at DESC
                     LIMIT 1
                     """);
             ResultSet rows = statement.executeQuery()) {
            require(rows.next(), "V24 live fixture requires one persisted Decision Input V3");
            return rows.getString(1).trim();
        }
    }

    private static long derivedRiskRowCount(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("SELECT count(*) FROM rbvm.derived_risk_result")) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static void proveAppendOnly(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.executeUpdate(
                            "UPDATE rbvm.derived_risk_result SET methodology_version = methodology_version")),
                    "runtime role must not UPDATE derived risk result history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.executeUpdate("DELETE FROM rbvm.derived_risk_result")),
                    "runtime role must not DELETE derived risk result history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.execute("TRUNCATE rbvm.derived_risk_result")),
                    "runtime role must not TRUNCATE derived risk result history");
        }
    }

    private static boolean rejected(SqlAction action) throws Exception {
        try {
            action.run();
            return false;
        } catch (SQLException exception) {
            return "42501".equals(exception.getSQLState());
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface
    private interface SqlAction {
        void run() throws Exception;
    }
}
