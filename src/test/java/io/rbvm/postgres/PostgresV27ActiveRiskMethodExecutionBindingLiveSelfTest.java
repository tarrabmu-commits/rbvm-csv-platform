package io.rbvm.postgres;

import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding;
import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding.ResultFamily;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy.MethodFamily;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;

/** Live PostgreSQL proof for V27 exact active-risk-method execution provenance binding. */
public final class PostgresV27ActiveRiskMethodExecutionBindingLiveSelfTest {
    private static final Instant T1 = Instant.parse("2026-08-23T05:10:00Z");

    private PostgresV27ActiveRiskMethodExecutionBindingLiveSelfTest() {
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
        require(schemaVersion >= 27,
                "V27 execution binding live test requires schema version 27 or newer, found "
                        + schemaVersion);

        JdbcConnectionFactory runtimeConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                "rbvm_runtime",
                "rbvm-live-test"
        );
        PostgresRiskMethodSelectionPolicyStore policies =
                new PostgresRiskMethodSelectionPolicyStore(runtimeConnections, false);
        PostgresRiskMethodSelectionPolicyActivationStore activations =
                new PostgresRiskMethodSelectionPolicyActivationStore(runtimeConnections, false);
        PostgresActiveRiskMethodExecutionBindingStore bindings =
                new PostgresActiveRiskMethodExecutionBindingStore(runtimeConnections, false);
        require(bindings.schemaVersion() >= 27,
                "execution binding store requires installed schema version 27 or newer");

        String snapshotSha = latestV3SnapshotSha(runtimeConnections);
        ActiveRiskMethodResultMaterializer existingNativeResults = (policy, inputSnapshotSha256) ->
                existingNativeResult(runtimeConnections, policy, inputSnapshotSha256);
        DefaultActiveRiskMethodExecutionBindingMaterializer materializer =
                new DefaultActiveRiskMethodExecutionBindingMaterializer(
                        policies,
                        activations,
                        existingNativeResults,
                        bindings
                );

        RbvmRiskMethodSelectionPolicy formula = policies.findByRevision(1).orElseThrow();
        RbvmRiskMethodSelectionPolicyActivationEvent activateFormula =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        5,
                        formula,
                        "binding-live-operator",
                        "bind Formula execution provenance",
                        T1
                );
        require(activations.install(activateFormula).status()
                        == RiskMethodSelectionPolicyActivationInstallResult.Status.INSERTED,
                "V27 fixture must append explicit Formula activation revision 5");

        ActiveRiskMethodExecutionBindingMaterializationResult formulaInserted =
                materializer.materialize(5, activateFormula.eventSha256(), snapshotSha);
        require(formulaInserted.installResult().status()
                        == ActiveRiskMethodExecutionBindingInstallResult.Status.INSERTED,
                "first exact Formula execution binding must append one row");
        RbvmActiveRiskMethodExecutionBinding formulaBinding = formulaInserted.binding();
        require(formulaBinding.methodFamily() == MethodFamily.RBVM_FORMULA,
                "Formula activation must bind RBVM_FORMULA family");
        require(formulaBinding.resultFamily() == ResultFamily.RBVM_FORMULA_RESULT,
                "Formula activation must bind Formula native result family");
        require(formulaBinding.activationEventSha256().equals(activateFormula.eventSha256()),
                "binding must retain exact historical activation event SHA");
        require(formulaBinding.policySha256().equals(formula.policySha256()),
                "binding must retain exact policy SHA");
        require(formulaBinding.inputSnapshotSha256().equals(snapshotSha),
                "binding must retain exact Decision Input SHA");
        require(bindings.findByBindingSha256(formulaBinding.bindingSha256()).orElseThrow()
                        .bindingSha256().equals(formulaBinding.bindingSha256()),
                "binding SHA lookup must rehydrate exact canonical binding");

        ActiveRiskMethodExecutionBindingMaterializationResult formulaReplay =
                materializer.materialize(5, activateFormula.eventSha256(), snapshotSha);
        require(formulaReplay.replayed(),
                "exact activation+input retry must replay immutable Formula binding");
        require(bindingRowCount(runtimeConnections) == 1,
                "Formula binding retry must not append a duplicate row");

        RbvmRiskMethodSelectionPolicy derived = policies.findByRevision(2).orElseThrow();
        RbvmRiskMethodSelectionPolicyActivationEvent activateDerived =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        6,
                        derived,
                        "binding-live-operator",
                        "bind derived execution provenance",
                        T1.plusSeconds(30)
                );
        require(activations.install(activateDerived).status()
                        == RiskMethodSelectionPolicyActivationInstallResult.Status.INSERTED,
                "V27 fixture must append explicit derived activation revision 6");

        ActiveRiskMethodExecutionBindingMaterializationResult derivedInserted =
                materializer.materialize(6, activateDerived.eventSha256(), snapshotSha);
        require(derivedInserted.installResult().status()
                        == ActiveRiskMethodExecutionBindingInstallResult.Status.INSERTED,
                "first exact derived execution binding must append one row");
        RbvmActiveRiskMethodExecutionBinding derivedBinding = derivedInserted.binding();
        require(derivedBinding.methodFamily() == MethodFamily.STANDARD_DERIVED,
                "derived activation must retain STANDARD_DERIVED family");
        require(derivedBinding.resultFamily() == ResultFamily.DERIVED_RISK_RESULT,
                "derived activation must bind derived native result family");
        require(derivedBinding.methodId().equals(derived.methodId())
                        && derivedBinding.methodVersion() == derived.methodVersion()
                        && derivedBinding.methodSha256().equals(derived.methodSha256()),
                "derived binding must retain exact selected method identity");
        require(bindings.findByActivationAndInput(
                        activateDerived.eventSha256(), snapshotSha).orElseThrow()
                        .bindingSha256().equals(derivedBinding.bindingSha256()),
                "activation+input lookup must preserve exact derived binding identity");
        require(bindingRowCount(runtimeConnections) == 2,
                "live fixture must contain exactly Formula plus derived execution bindings");

        RbvmRiskMethodSelectionPolicyActivationEvent invalidDerivedActivation =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        7,
                        derived,
                        "binding-live-operator",
                        "prove result identity FK",
                        T1.plusSeconds(60)
                );
        require(activations.install(invalidDerivedActivation).status()
                        == RiskMethodSelectionPolicyActivationInstallResult.Status.INSERTED,
                "FK proof requires a fresh exact activation execution key");
        proveDatabaseRejectsCrossMethodResult(
                runtimeConnections,
                invalidDerivedActivation,
                derived,
                snapshotSha
        );
        proveAppendOnly(runtimeConnections);

        System.out.println(
                "PostgresV27ActiveRiskMethodExecutionBindingLiveSelfTest: PASS schema="
                        + schemaVersion
                        + " formula=PASS derived=PASS exact_activation=PASS exact_policy=PASS "
                        + "exact_input=PASS replay=PASS db_method_result_fk=PASS append_only=PASS"
        );
    }

    private static ActiveRiskMethodNativeResult existingNativeResult(
            JdbcConnectionFactory connections,
            RbvmRiskMethodSelectionPolicy policy,
            String snapshotSha
    ) throws IOException {
        try {
            if (policy.methodFamily() == MethodFamily.RBVM_FORMULA) {
                try (Connection connection = connections.open();
                     PreparedStatement statement = connection.prepareStatement("""
                             SELECT formula_id, formula_version, formula_sha256, explanation_sha256
                             FROM rbvm.formula_result
                             WHERE input_snapshot_sha256 = ?
                               AND formula_id = ?
                               AND formula_version = ?
                               AND formula_sha256 = ?
                             """)) {
                    statement.setString(1, snapshotSha);
                    statement.setString(2, policy.methodId());
                    statement.setInt(3, policy.methodVersion());
                    statement.setString(4, policy.methodSha256());
                    try (ResultSet rows = statement.executeQuery()) {
                        require(rows.next(), "Formula live result must already exist for exact snapshot/method");
                        ActiveRiskMethodNativeResult result = new ActiveRiskMethodNativeResult(
                                snapshotSha,
                                policy.methodFamily(),
                                rows.getString(1),
                                rows.getInt(2),
                                rows.getString(3).trim(),
                                ResultFamily.RBVM_FORMULA_RESULT,
                                rows.getString(4).trim()
                        );
                        require(!rows.next(), "Formula exact snapshot/method identity must resolve one row");
                        return result;
                    }
                }
            }

            try (Connection connection = connections.open();
                 PreparedStatement statement = connection.prepareStatement("""
                         SELECT methodology_id, methodology_version, methodology_sha256, result_sha256
                         FROM rbvm.derived_risk_result
                         WHERE input_snapshot_sha256 = ?
                           AND methodology_id = ?
                           AND methodology_version = ?
                           AND methodology_sha256 = ?
                         """)) {
                statement.setString(1, snapshotSha);
                statement.setString(2, policy.methodId());
                statement.setInt(3, policy.methodVersion());
                statement.setString(4, policy.methodSha256());
                try (ResultSet rows = statement.executeQuery()) {
                    require(rows.next(), "derived live result must already exist for exact snapshot/method");
                    ActiveRiskMethodNativeResult result = new ActiveRiskMethodNativeResult(
                            snapshotSha,
                            policy.methodFamily(),
                            rows.getString(1),
                            rows.getInt(2),
                            rows.getString(3).trim(),
                            ResultFamily.DERIVED_RISK_RESULT,
                            rows.getString(4).trim()
                    );
                    require(!rows.next(), "derived exact snapshot/method identity must resolve one row");
                    return result;
                }
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("Could not resolve existing native risk result", exception);
        }
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
            require(rows.next(), "V27 live fixture requires one persisted Decision Input V3");
            return rows.getString(1).trim();
        }
    }

    private static long bindingRowCount(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT count(*) FROM rbvm.active_risk_method_execution_binding")) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static void proveDatabaseRejectsCrossMethodResult(
            JdbcConnectionFactory connections,
            RbvmRiskMethodSelectionPolicyActivationEvent activation,
            RbvmRiskMethodSelectionPolicy policy,
            String snapshotSha
    ) throws Exception {
        String wrongDerivedResultSha = anotherDerivedResultSha(
                connections,
                snapshotSha,
                policy.methodId()
        );
        RbvmActiveRiskMethodExecutionBinding invalid = RbvmActiveRiskMethodExecutionBinding.bind(
                activation,
                policy,
                snapshotSha,
                ResultFamily.DERIVED_RISK_RESULT,
                wrongDerivedResultSha
        );
        PostgresActiveRiskMethodExecutionBindingStore store =
                new PostgresActiveRiskMethodExecutionBindingStore(connections, false);
        require(rejectedForeignKey(() -> store.install(invalid)),
                "PostgreSQL must reject binding a selected methodology to another methodology result");
        require(bindingRowCount(connections) == 2,
                "rejected cross-method binding must not append provenance");
    }

    private static String anotherDerivedResultSha(
            JdbcConnectionFactory connections,
            String snapshotSha,
            String selectedMethodId
    ) throws Exception {
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT result_sha256
                     FROM rbvm.derived_risk_result
                     WHERE input_snapshot_sha256 = ?
                       AND methodology_id <> ?
                     LIMIT 1
                     """)) {
            statement.setString(1, snapshotSha);
            statement.setString(2, selectedMethodId);
            try (ResultSet rows = statement.executeQuery()) {
                require(rows.next(), "V27 live fixture requires a second derived methodology result");
                return rows.getString(1).trim();
            }
        }
    }

    private static void proveAppendOnly(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejectedPrivilege(() -> statement.executeUpdate(
                            "UPDATE rbvm.active_risk_method_execution_binding "
                                    + "SET method_version = method_version")),
                    "runtime role must not UPDATE execution binding history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejectedPrivilege(() -> statement.executeUpdate(
                            "DELETE FROM rbvm.active_risk_method_execution_binding")),
                    "runtime role must not DELETE execution binding history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejectedPrivilege(() -> statement.execute(
                            "TRUNCATE rbvm.active_risk_method_execution_binding")),
                    "runtime role must not TRUNCATE execution binding history");
        }
    }

    private static boolean rejectedForeignKey(SqlAction action) throws Exception {
        try {
            action.run();
            return false;
        } catch (IOException exception) {
            return exception.getMessage().contains("[SQLState=23503]");
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
