package io.rbvm.postgres;

import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/** Live PostgreSQL coverage for V25 exact primary risk-method selection policy persistence. */
public final class PostgresV25RiskMethodSelectionPolicyLiveSelfTest {
    private PostgresV25RiskMethodSelectionPolicyLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");

        JdbcConnectionFactory ownerConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        require(new PostgresMigrator(ownerConnections).installedVersion() >= 25,
                "V25 risk method selection live test requires schema version 25 or newer");

        JdbcConnectionFactory runtimeConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                "rbvm_runtime",
                "rbvm-live-test"
        );
        PostgresRiskMethodSelectionPolicyStore store =
                new PostgresRiskMethodSelectionPolicyStore(runtimeConnections, false);
        require(store.schemaVersion() >= 25,
                "risk method selection store must bind schema version 25 or newer");

        RbvmRiskMethodSelectionPolicy formula = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RiskMethodSelectionPolicyInstallResult inserted = store.install(formula);
        require(inserted.status() == RiskMethodSelectionPolicyInstallResult.Status.INSERTED,
                "first Formula policy revision must append one row");
        RiskMethodSelectionPolicyInstallResult replayed = store.install(formula);
        require(replayed.status() == RiskMethodSelectionPolicyInstallResult.Status.REPLAYED,
                "exact Formula policy retry must replay without duplicate row");
        require(store.findByRevision(1).orElseThrow().policySha256().equals(formula.policySha256()),
                "revision lookup must preserve exact Formula policy SHA");
        require(store.findByPolicySha256(formula.policySha256()).orElseThrow().methodSha256()
                        .equals(formula.methodSha256()),
                "SHA lookup must preserve exact selected Formula identity");

        RbvmDerivedRiskMethodology.Definition conflictDefinition =
                RbvmDerivedRiskMethodologyCatalog.definitions().get(0);
        RbvmRiskMethodSelectionPolicy conflicting =
                RbvmRiskMethodSelectionPolicy.derived(1, conflictDefinition);
        RiskMethodSelectionPolicyInstallResult conflict = store.install(conflicting);
        require(conflict.status() == RiskMethodSelectionPolicyInstallResult.Status.REVISION_CONFLICT,
                "same revision with a different method identity must fail closed as a conflict");
        require(conflict.existingPolicySha256().equals(formula.policySha256()),
                "revision conflict must identify the immutable existing policy SHA");

        int revision = 2;
        for (RbvmDerivedRiskMethodology.Definition definition
                : RbvmDerivedRiskMethodologyCatalog.definitions()) {
            RbvmRiskMethodSelectionPolicy policy =
                    RbvmRiskMethodSelectionPolicy.derived(revision, definition);
            RiskMethodSelectionPolicyInstallResult result = store.install(policy);
            require(result.status() == RiskMethodSelectionPolicyInstallResult.Status.INSERTED,
                    "each derived methodology must be installable as its own explicit policy revision");
            RbvmRiskMethodSelectionPolicy stored = store.findByRevision(revision).orElseThrow();
            require(stored.methodFamily()
                            == RbvmRiskMethodSelectionPolicy.MethodFamily.STANDARD_DERIVED,
                    "derived policy must retain STANDARD_DERIVED family");
            require(stored.methodId().equals(definition.methodologyId()),
                    "derived policy must retain exact methodology ID");
            require(stored.methodVersion() == definition.version(),
                    "derived policy must retain exact methodology version");
            require(stored.methodSha256().equals(definition.methodologySha256()),
                    "derived policy must retain exact methodology SHA");
            revision++;
        }

        require(policyRowCount(runtimeConnections) == 3,
                "V25 live fixture must contain Formula plus two independent derived policy revisions");
        proveAppendOnly(runtimeConnections);

        System.out.println(
                "PostgresV25RiskMethodSelectionPolicyLiveSelfTest: PASS schema>=25 "
                        + "insert=PASS replay=PASS revision_conflict=PASS exact_identity=PASS "
                        + "formula=PASS derived=2 append_only=PASS no_default=PASS"
        );
    }

    private static long policyRowCount(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT count(*) FROM rbvm.risk_method_selection_policy")) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static void proveAppendOnly(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.executeUpdate(
                            "UPDATE rbvm.risk_method_selection_policy "
                                    + "SET method_version = method_version")),
                    "runtime role must not UPDATE risk method selection policy history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.executeUpdate(
                            "DELETE FROM rbvm.risk_method_selection_policy")),
                    "runtime role must not DELETE risk method selection policy history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.execute(
                            "TRUNCATE rbvm.risk_method_selection_policy")),
                    "runtime role must not TRUNCATE risk method selection policy history");
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
