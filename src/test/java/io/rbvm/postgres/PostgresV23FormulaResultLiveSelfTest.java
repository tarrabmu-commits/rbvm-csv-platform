package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmFormulaV1;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/** Live PostgreSQL coverage for V23 Formula-result materialization, persistence, and replay. */
public final class PostgresV23FormulaResultLiveSelfTest {
    private PostgresV23FormulaResultLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");

        JdbcConnectionFactory ownerConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        int schemaVersion = new PostgresMigrator(ownerConnections).migrate();
        require(schemaVersion == 23, "expected schema version 23, found " + schemaVersion);

        invokeLegacy("seedCanonicalFinding", new Class<?>[]{JdbcConnectionFactory.class}, ownerConnections);
        invokeV22("seedScopedEvidence", new Class<?>[]{JdbcConnectionFactory.class}, ownerConnections);
        invokeLegacy("installRuntimeRole", new Class<?>[]{JdbcConnectionFactory.class}, ownerConnections);
        invokeLegacy("setRuntimePassword", new Class<?>[]{JdbcConnectionFactory.class}, ownerConnections);

        JdbcConnectionFactory runtimeConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                "rbvm_runtime",
                "rbvm-live-test"
        );
        invokeV22(
                "exerciseV3",
                new Class<?>[]{JdbcConnectionFactory.class, int.class},
                runtimeConnections,
                schemaVersion
        );
        invokeV22(
                "proveAppendOnlyPrivileges",
                new Class<?>[]{JdbcConnectionFactory.class},
                runtimeConnections
        );

        String snapshotSha = latestV3SnapshotSha(runtimeConnections);
        PostgresDecisionInputSnapshotStore decisionInputs = new PostgresDecisionInputSnapshotStore(
                runtimeConnections,
                false
        );
        RbvmDecisionInputSnapshot snapshot = decisionInputs.findBySha256(snapshotSha).orElseThrow();
        require(snapshot.isV3(), "persisted Formula input must be Decision Input V3");

        PostgresDecisionInputEvidenceResolver resolver = new PostgresDecisionInputEvidenceResolver(
                runtimeConnections,
                schemaVersion
        );
        PostgresFormulaResultStore formulaResults = new PostgresFormulaResultStore(
                runtimeConnections,
                false
        );
        FormulaResultReplayVerifier replayVerifier = new FormulaResultReplayVerifier(
                formulaResults,
                decisionInputs,
                resolver
        );
        DefaultFormulaResultMaterializer materializer = new DefaultFormulaResultMaterializer(
                decisionInputs,
                resolver,
                formulaResults,
                replayVerifier
        );

        FormulaResultMaterializationResult inserted = materializer.materialize(snapshotSha);
        require(inserted.installResult().status() == FormulaResultInstallResult.Status.INSERTED,
                "first production Formula materialization must append exactly one row");
        require(inserted.explanation().inputSnapshotSha256().equals(snapshot.snapshotSha256()),
                "materialization must evaluate only the exact persisted Decision Input identity");

        FormulaResultMaterializationResult replayed = materializer.materialize(snapshotSha);
        require(replayed.installResult().status() == FormulaResultInstallResult.Status.REPLAYED,
                "exact Formula materialization retry must replay without a second row");
        require(replayed.explanation().canonicalSha256()
                        .equals(inserted.explanation().canonicalSha256()),
                "exact materialization replay must preserve canonical explanation identity");

        StoredFormulaResult stored = formulaResults
                .findByExplanationSha256(inserted.explanation().canonicalSha256())
                .orElseThrow();
        require(stored.inputSnapshotSha256().equals(snapshot.snapshotSha256()),
                "stored Formula result must retain exact input snapshot identity");
        require(stored.formulaSha256().equals(RbvmFormulaV1.FORMULA_SHA256),
                "stored Formula result must retain accepted Formula V1 identity");
        require(stored.explanationSha256().equals(inserted.explanation().canonicalSha256()),
                "stored Formula result must retain canonical explanation identity");

        replayVerifier.verify(stored);
        replayVerifier.verifyBySnapshotAndFormula(
                snapshot.snapshotSha256(),
                RbvmFormulaV1.FORMULA_SHA256
        );

        proveAppendOnly(runtimeConnections);
        require(formulaRowCount(runtimeConnections) == 1,
                "Formula materialization retries must not create duplicate rows");

        System.out.println(
                "PostgresV23FormulaResultLiveSelfTest: PASS schema=23 materialization=PASS "
                        + "formula_result=PASS decision_v3_append_only=PASS idempotency=PASS "
                        + "replay=PASS append_only=PASS"
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
            require(rows.next(), "V23 live fixture must contain one persisted Decision Input V3");
            return rows.getString(1).trim();
        }
    }

    private static long formulaRowCount(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("SELECT count(*) FROM rbvm.formula_result")) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static void proveAppendOnly(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.executeUpdate(
                            "UPDATE rbvm.formula_result SET formula_version = formula_version")),
                    "runtime role must not UPDATE Formula result history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.executeUpdate("DELETE FROM rbvm.formula_result")),
                    "runtime role must not DELETE Formula result history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.execute("TRUNCATE rbvm.formula_result")),
                    "runtime role must not TRUNCATE Formula result history");
        }
    }

    private static void invokeLegacy(String name, Class<?>[] parameterTypes, Object... args)
            throws Exception {
        invoke(PostgresV20LiveSelfTest.class, name, parameterTypes, args);
    }

    private static void invokeV22(String name, Class<?>[] parameterTypes, Object... args)
            throws Exception {
        invoke(PostgresV22LiveSelfTest.class, name, parameterTypes, args);
    }

    private static void invoke(
            Class<?> owner,
            String name,
            Class<?>[] parameterTypes,
            Object... args
    ) throws Exception {
        Method method = owner.getDeclaredMethod(name, parameterTypes);
        method.setAccessible(true);
        try {
            method.invoke(null, args);
        } catch (InvocationTargetException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof Exception checked) throw checked;
            if (cause instanceof Error error) throw error;
            throw new IllegalStateException("PostgreSQL live fixture setup failed", cause);
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
