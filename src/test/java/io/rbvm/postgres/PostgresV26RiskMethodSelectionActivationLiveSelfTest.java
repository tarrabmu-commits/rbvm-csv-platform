package io.rbvm.postgres;

import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;

/** Live PostgreSQL proof for V26 explicit active-policy pointer semantics. */
public final class PostgresV26RiskMethodSelectionActivationLiveSelfTest {
    private static final Instant T1 = Instant.parse("2026-08-23T05:00:00Z");

    private PostgresV26RiskMethodSelectionActivationLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");

        JdbcConnectionFactory ownerConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        int schemaVersion = new PostgresMigrator(ownerConnections).installedVersion();
        require(schemaVersion >= 26,
                "V26 activation live test requires schema version >=26, found " + schemaVersion);

        JdbcConnectionFactory runtimeConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                "rbvm_runtime",
                "rbvm-live-test"
        );
        PostgresRiskMethodSelectionPolicyStore policies =
                new PostgresRiskMethodSelectionPolicyStore(runtimeConnections, false);
        PostgresRiskMethodSelectionPolicyActivationStore activations =
                new PostgresRiskMethodSelectionPolicyActivationStore(runtimeConnections, false);
        require(activations.schemaVersion() >= 26,
                "activation store must bind installed schema version >=26");

        RbvmRiskMethodSelectionPolicy formula = policies.findByRevision(1).orElseThrow();
        RbvmRiskMethodSelectionPolicy derived = policies.findByRevision(2).orElseThrow();

        RbvmRiskMethodSelectionPolicyActivationEvent activateFormula =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        1,
                        formula,
                        "activation-live-operator",
                        "activate Formula policy revision 1",
                        T1
                );
        RiskMethodSelectionPolicyActivationInstallResult inserted =
                activations.install(activateFormula);
        require(inserted.status()
                        == RiskMethodSelectionPolicyActivationInstallResult.Status.INSERTED,
                "first activation event must append exactly once");
        RiskMethodSelectionPolicyActivationInstallResult replayed =
                activations.install(activateFormula);
        require(replayed.status()
                        == RiskMethodSelectionPolicyActivationInstallResult.Status.REPLAYED,
                "exact activation retry must replay without another row");
        require(activations.findByActivationRevision(1).orElseThrow().eventSha256()
                        .equals(activateFormula.eventSha256()),
                "activation revision lookup must preserve exact event SHA");
        require(activations.findByEventSha256(activateFormula.eventSha256()).orElseThrow()
                        .policySha256().equals(formula.policySha256()),
                "activation SHA lookup must preserve exact policy identity");
        require(activations.current().orElseThrow().activationRevision() == 1,
                "first explicit activation revision must be current");
        require(activePolicyRevision(runtimeConnections) == 1,
                "active view must resolve exact Formula policy revision 1");

        RbvmRiskMethodSelectionPolicyActivationEvent conflictingRevision =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        1,
                        derived,
                        "activation-live-operator",
                        "conflicting activation revision",
                        T1.plusSeconds(30)
                );
        RiskMethodSelectionPolicyActivationInstallResult conflict =
                activations.install(conflictingRevision);
        require(conflict.status()
                        == RiskMethodSelectionPolicyActivationInstallResult.Status.REVISION_CONFLICT,
                "same activation revision with different identity must conflict");
        require(conflict.observedEventSha256().equals(activateFormula.eventSha256()),
                "activation revision conflict must identify immutable existing event SHA");

        RbvmRiskMethodSelectionPolicy unpersisted =
                RbvmRiskMethodSelectionPolicy.formulaV1(99);
        RbvmRiskMethodSelectionPolicyActivationEvent missingPolicy =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        2,
                        unpersisted,
                        "activation-live-operator",
                        "must fail because policy revision 99 was never installed",
                        T1.plusSeconds(60)
                );
        require(rejectedMissingPolicy(() -> activations.install(missingPolicy)),
                "ACTIVE event must fail closed unless exact policy revision+SHA already exists");

        RbvmRiskMethodSelectionPolicyActivationEvent activateDerived =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        3,
                        derived,
                        "activation-live-operator",
                        "activate derived policy revision 2",
                        T1.plusSeconds(90)
                );
        require(activations.install(activateDerived).status()
                        == RiskMethodSelectionPolicyActivationInstallResult.Status.INSERTED,
                "greater explicit activation revision must append");
        require(activations.current().orElseThrow().activationRevision() == 3,
                "activation current state must follow activation revision, not policy revision");
        require(activePolicyRevision(runtimeConnections) == 2,
                "active view must resolve exact referenced policy revision 2");

        RbvmRiskMethodSelectionPolicyActivationEvent staleClear =
                RbvmRiskMethodSelectionPolicyActivationEvent.clear(
                        2,
                        "activation-live-operator",
                        "stale clear must not alter current state",
                        T1.plusSeconds(120)
                );
        RiskMethodSelectionPolicyActivationInstallResult stale = activations.install(staleClear);
        require(stale.status()
                        == RiskMethodSelectionPolicyActivationInstallResult.Status.STALE_ACTIVATION_REVISION,
                "new lower activation revision must fail closed as stale");
        require(stale.observedActivationRevision() == 3,
                "stale activation result must identify the greater current activation revision");
        require(activationRowCount(runtimeConnections) == 2,
                "stale/conflicting/missing-policy attempts must not append rows");

        RbvmRiskMethodSelectionPolicyActivationEvent clear =
                RbvmRiskMethodSelectionPolicyActivationEvent.clear(
                        4,
                        "activation-live-operator",
                        "explicitly clear active policy",
                        T1.plusSeconds(150)
                );
        require(activations.install(clear).status()
                        == RiskMethodSelectionPolicyActivationInstallResult.Status.INSERTED,
                "explicit CLEARED event must append");
        RbvmRiskMethodSelectionPolicyActivationEvent current =
                activations.current().orElseThrow();
        require(current.activationRevision() == 4,
                "explicit clear must become current by activation revision");
        require(current.activationState()
                        == RbvmRiskMethodSelectionPolicyActivationEvent.ActivationState.CLEARED,
                "current activation state must preserve explicit CLEARED");
        require(activePolicyRowCount(runtimeConnections) == 0,
                "active policy view must be empty after explicit CLEARED");
        require(currentActivationState(runtimeConnections).equals("CLEARED"),
                "current view must distinguish CLEARED from never activated");
        require(activationRowCount(runtimeConnections) == 3,
                "live fixture must retain three immutable accepted activation events");

        proveAppendOnly(runtimeConnections);

        System.out.println(
                "PostgresV26RiskMethodSelectionActivationLiveSelfTest: PASS schema>=26 "
                        + "activate=PASS replay=PASS revision_conflict=PASS missing_policy=PASS "
                        + "stale_revision=PASS exact_pointer=PASS clear=PASS append_only=PASS"
        );
    }

    private static int activePolicyRevision(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("""
                     SELECT policy_revision
                     FROM rbvm.active_risk_method_selection_policy
                     """)) {
            require(rows.next(), "active policy view must contain one explicit ACTIVE row");
            int revision = rows.getInt(1);
            require(!rows.next(), "active policy view must contain at most one row per tenant");
            return revision;
        }
    }

    private static String currentActivationState(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("""
                     SELECT activation_state
                     FROM rbvm.current_risk_method_selection_policy_activation
                     """)) {
            require(rows.next(), "current activation view must retain explicit CLEARED event");
            String state = rows.getString(1);
            require(!rows.next(), "current activation view must contain at most one row per tenant");
            return state;
        }
    }

    private static long activePolicyRowCount(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT count(*) FROM rbvm.active_risk_method_selection_policy")) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static long activationRowCount(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT count(*) FROM rbvm.risk_method_selection_policy_activation_event")) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static void proveAppendOnly(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejectedPrivilege(() -> statement.executeUpdate(
                            "UPDATE rbvm.risk_method_selection_policy_activation_event "
                                    + "SET change_note = change_note")),
                    "runtime role must not UPDATE activation history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejectedPrivilege(() -> statement.executeUpdate(
                            "DELETE FROM rbvm.risk_method_selection_policy_activation_event")),
                    "runtime role must not DELETE activation history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejectedPrivilege(() -> statement.execute(
                            "TRUNCATE rbvm.risk_method_selection_policy_activation_event")),
                    "runtime role must not TRUNCATE activation history");
        }
    }

    private static boolean rejectedMissingPolicy(SqlAction action) throws Exception {
        try {
            action.run();
            return false;
        } catch (IOException exception) {
            return exception.getMessage().contains("Exact Risk Method Selection Policy");
        }
    }

    private static boolean rejectedPrivilege(SqlAction action) throws Exception {
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
