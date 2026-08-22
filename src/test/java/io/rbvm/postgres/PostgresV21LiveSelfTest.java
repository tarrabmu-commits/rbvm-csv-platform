package io.rbvm.postgres;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;

/**
 * Live PostgreSQL integration coverage for V21 Finding-context association persistence.
 *
 * <p>The existing V18-V20 integration body is deliberately reused through its test helpers so the
 * new schema gate extends rather than replaces the established managed-asset/link/Decision-Input
 * coverage. This class then proves V21 inserts, current views, and append-only runtime privileges
 * against a real PostgreSQL service.</p>
 */
public final class PostgresV21LiveSelfTest {
    private static final UUID FINDING_ID = UUID.fromString("70000000-0000-4000-8000-000000000001");

    private PostgresV21LiveSelfTest() {
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
        require(schemaVersion == 21, "expected schema version 21, found " + schemaVersion);

        invokeLegacy("seedCanonicalFinding", new Class<?>[]{JdbcConnectionFactory.class}, ownerConnections);
        invokeLegacy("installRuntimeRole", new Class<?>[]{JdbcConnectionFactory.class}, ownerConnections);
        invokeLegacy("setRuntimePassword", new Class<?>[]{JdbcConnectionFactory.class}, ownerConnections);

        JdbcConnectionFactory runtimeConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                "rbvm_runtime",
                "rbvm-live-test"
        );

        invokeLegacy(
                "exerciseManagedAssetLinkAndDecisionInput",
                new Class<?>[]{JdbcConnectionFactory.class, int.class},
                runtimeConnections,
                schemaVersion
        );
        invokeLegacy(
                "proveAppendOnlyPrivileges",
                new Class<?>[]{JdbcConnectionFactory.class},
                runtimeConnections
        );

        exerciseFindingContextAssociations(runtimeConnections);
        proveV21AppendOnlyPrivileges(runtimeConnections);

        System.out.println(
                "PostgresV21LiveSelfTest: PASS schema=21 managed_asset=PASS scanner_link=PASS "
                        + "decision_v2=PASS finding_context_association=PASS append_only=PASS"
        );
    }

    private static void exerciseFindingContextAssociations(JdbcConnectionFactory connections)
            throws Exception {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            int insertedReachability = statement.executeUpdate("""
                    INSERT INTO rbvm.finding_reachability_scope_link_event(
                        id, tenant_id, finding_id, revision, link_status,
                        origin_scope, origin_label_normalized, transport_protocol, target_port,
                        link_method, evidence_sha256, changed_by, change_note, recorded_at
                    ) VALUES (
                        '91000000-0000-4000-8000-000000000001',
                        '10000000-0000-4000-8000-000000000001',
                        '70000000-0000-4000-8000-000000000001',
                        1, 'LINKED', 'INTERNET', 'edge probe', 'TCP', 443,
                        'CUSTOMER_CONFIRMED',
                        'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                        'live-test-operator', 'finding serves the confirmed endpoint',
                        '2026-08-21T00:07:00Z'
                    )
                    """);
            require(insertedReachability == 1, "runtime must INSERT reachability association event");

            int insertedService = statement.executeUpdate("""
                    INSERT INTO rbvm.finding_business_service_link_event(
                        id, tenant_id, finding_id, revision, link_status,
                        business_service_normalized, link_method, evidence_sha256,
                        changed_by, change_note, recorded_at
                    ) VALUES (
                        '92000000-0000-4000-8000-000000000001',
                        '10000000-0000-4000-8000-000000000001',
                        '70000000-0000-4000-8000-000000000001',
                        1, 'LINKED', 'payments', 'CUSTOMER_CONFIRMED',
                        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                        'live-test-operator', 'finding affects the payments service',
                        '2026-08-21T00:07:00Z'
                    )
                    """);
            require(insertedService == 1, "runtime must INSERT business-service association event");
        }

        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            try (ResultSet rows = statement.executeQuery("""
                    SELECT finding_id, link_status, origin_scope, origin_label_normalized,
                           transport_protocol, target_port
                    FROM rbvm.current_finding_reachability_scope_link
                    WHERE finding_id = '70000000-0000-4000-8000-000000000001'
                    """)) {
                require(rows.next(), "current reachability association view must expose revision 1");
                require(FINDING_ID.equals(rows.getObject(1, UUID.class)), "reachability finding ID mismatch");
                require("LINKED".equals(rows.getString(2)), "reachability state must remain LINKED");
                require("INTERNET".equals(rows.getString(3)), "reachability origin scope mismatch");
                require("edge probe".equals(rows.getString(4)), "reachability origin label mismatch");
                require("TCP".equals(rows.getString(5)), "reachability protocol mismatch");
                require(rows.getInt(6) == 443, "reachability target port mismatch");
                require(!rows.next(), "only one reachability logical stream expected");
            }

            try (ResultSet rows = statement.executeQuery("""
                    SELECT finding_id, link_status, business_service_normalized
                    FROM rbvm.current_finding_business_service_link
                    WHERE finding_id = '70000000-0000-4000-8000-000000000001'
                    """)) {
                require(rows.next(), "current business-service association view must expose revision 1");
                require(FINDING_ID.equals(rows.getObject(1, UUID.class)), "service finding ID mismatch");
                require("LINKED".equals(rows.getString(2)), "service state must remain LINKED");
                require("payments".equals(rows.getString(3)), "normalized business service mismatch");
                require(!rows.next(), "only one business-service logical stream expected");
            }
        }
    }

    private static void proveV21AppendOnlyPrivileges(JdbcConnectionFactory connections)
            throws Exception {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.executeUpdate(
                            "UPDATE rbvm.finding_reachability_scope_link_event "
                                    + "SET change_note = 'forbidden'")),
                    "runtime role must not UPDATE Finding reachability association history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.executeUpdate(
                            "DELETE FROM rbvm.finding_business_service_link_event")),
                    "runtime role must not DELETE Finding business-service association history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.execute(
                            "TRUNCATE rbvm.finding_reachability_scope_link_event")),
                    "runtime role must not TRUNCATE Finding reachability association history");
        }
    }

    private static void invokeLegacy(String name, Class<?>[] parameterTypes, Object... args)
            throws Exception {
        Method method = PostgresV20LiveSelfTest.class.getDeclaredMethod(name, parameterTypes);
        method.setAccessible(true);
        try {
            method.invoke(null, args);
        } catch (InvocationTargetException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof Exception checked) {
                throw checked;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new IllegalStateException("Legacy PostgreSQL coverage failed", cause);
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
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @FunctionalInterface
    private interface SqlAction {
        void run() throws Exception;
    }
}
