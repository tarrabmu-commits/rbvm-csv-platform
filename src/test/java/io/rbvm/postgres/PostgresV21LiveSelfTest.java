package io.rbvm.postgres;

import io.rbvm.context.FindingBusinessServiceLink;
import io.rbvm.context.FindingBusinessServiceLinkRegistry;
import io.rbvm.context.FindingReachabilityScopeLink;
import io.rbvm.context.FindingReachabilityScopeLink.OriginScope;
import io.rbvm.context.FindingReachabilityScopeLink.TransportProtocol;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * Live PostgreSQL integration coverage for V21 Finding-context association persistence and
 * optimistic-concurrency registries.
 *
 * <p>The existing V18-V20 integration body is deliberately reused through its test helpers so the
 * new schema gate extends rather than replaces the established managed-asset/link/Decision-Input
 * coverage.</p>
 */
public final class PostgresV21LiveSelfTest {
    private static final UUID FINDING_ID = UUID.fromString("70000000-0000-4000-8000-000000000001");
    private static final UUID MISSING_FINDING_ID = UUID.fromString("70000000-0000-4000-8000-000000000099");
    private static final Instant T7 = Instant.parse("2026-08-21T00:07:00Z");
    private static final Instant T8 = Instant.parse("2026-08-21T00:08:00Z");

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

        exerciseReachabilityRegistry(runtimeConnections, schemaVersion);
        exerciseBusinessServiceRegistry(runtimeConnections, schemaVersion);
        proveV21AppendOnlyPrivileges(runtimeConnections);

        System.out.println(
                "PostgresV21LiveSelfTest: PASS schema=21 managed_asset=PASS scanner_link=PASS "
                        + "decision_v2=PASS finding_context_registry=PASS append_only=PASS"
        );
    }

    private static void exerciseReachabilityRegistry(
            JdbcConnectionFactory connections,
            int schemaVersion
    ) throws Exception {
        PostgresFindingReachabilityScopeLinkRegistry registry =
                new PostgresFindingReachabilityScopeLinkRegistry(
                        connections,
                        schemaVersion,
                        Clock.fixed(T7, ZoneOffset.UTC)
                );
        FindingReachabilityScopeLink.ChangeDraft linked =
                FindingReachabilityScopeLink.ChangeDraft.linked(
                        OriginScope.INTERNET,
                        "Edge Probe",
                        TransportProtocol.TCP,
                        443,
                        "live-test-operator",
                        "finding serves the confirmed endpoint"
                );

        var first = registry.revise(FINDING_ID, 0, linked);
        require(first.status() == FindingReachabilityScopeLinkRegistry.MutationStatus.UPDATED,
                "first reachability association must append revision 1");
        require(first.current().revision() == 1, "reachability revision 1 expected");
        require(first.current().recordedAt().equals(T7), "reachability registry clock must be exact");
        require("edge probe".equals(first.current().originLabel()),
                "reachability origin label must be normalized");
        UUID firstEventId = first.current().eventId();

        var replay = registry.revise(FINDING_ID, 0, linked);
        require(replay.status() == FindingReachabilityScopeLinkRegistry.MutationStatus.REPLAYED,
                "exact reachability retry must replay");
        require(replay.current().eventId().equals(firstEventId),
                "reachability replay must retain original event");

        var conflict = registry.revise(
                FINDING_ID,
                0,
                FindingReachabilityScopeLink.ChangeDraft.unlinked(
                        OriginScope.INTERNET,
                        "edge probe",
                        TransportProtocol.TCP,
                        443,
                        "live-test-operator",
                        "stale expected revision"
                )
        );
        require(conflict.status() == FindingReachabilityScopeLinkRegistry.MutationStatus.REVISION_CONFLICT,
                "stale reachability mutation must conflict");
        require(conflict.current().eventId().equals(firstEventId),
                "reachability conflict must return current event");

        var current = registry.current(
                FINDING_ID,
                OriginScope.INTERNET,
                "EDGE PROBE",
                TransportProtocol.TCP,
                443
        );
        require(current.findingExists(), "reachability current lookup must resolve Finding");
        require(current.currentOptional().orElseThrow().eventId().equals(firstEventId),
                "reachability current lookup must resolve revision 1");
        require(registry.history(
                        FINDING_ID,
                        OriginScope.INTERNET,
                        "edge probe",
                        TransportProtocol.TCP,
                        443,
                        10,
                        null
                ).orElseThrow().events().size() == 1,
                "reachability replay must not append history");
        require(registry.listCurrent(FINDING_ID, 10, null).orElseThrow().links().size() == 1,
                "reachability current list must expose one logical stream");

        var missing = registry.revise(MISSING_FINDING_ID, 0, linked);
        require(missing.status() == FindingReachabilityScopeLinkRegistry.MutationStatus.FINDING_NOT_FOUND,
                "missing Finding must not create reachability history");

        PostgresFindingReachabilityScopeLinkRegistry later =
                new PostgresFindingReachabilityScopeLinkRegistry(
                        connections,
                        schemaVersion,
                        Clock.fixed(T8, ZoneOffset.UTC)
                );
        var unlink = later.revise(
                FINDING_ID,
                1,
                FindingReachabilityScopeLink.ChangeDraft.unlinked(
                        OriginScope.INTERNET,
                        "edge probe",
                        TransportProtocol.TCP,
                        443,
                        "live-test-operator",
                        "explicit customer unlink"
                )
        );
        require(unlink.status() == FindingReachabilityScopeLinkRegistry.MutationStatus.UPDATED,
                "reachability unlink must append revision 2");
        require(unlink.current().revision() == 2, "reachability revision 2 expected");
        require(unlink.current().linkStatus() == FindingReachabilityScopeLink.LinkStatus.UNLINKED,
                "reachability current state must preserve explicit UNLINKED");
        require(later.history(
                        FINDING_ID,
                        OriginScope.INTERNET,
                        "edge probe",
                        TransportProtocol.TCP,
                        443,
                        10,
                        null
                ).orElseThrow().events().size() == 2,
                "reachability history must preserve both revisions");
    }

    private static void exerciseBusinessServiceRegistry(
            JdbcConnectionFactory connections,
            int schemaVersion
    ) throws Exception {
        PostgresFindingBusinessServiceLinkRegistry registry =
                new PostgresFindingBusinessServiceLinkRegistry(
                        connections,
                        schemaVersion,
                        Clock.fixed(T7, ZoneOffset.UTC)
                );
        FindingBusinessServiceLink.ChangeDraft linked =
                FindingBusinessServiceLink.ChangeDraft.linked(
                        "Payments",
                        "live-test-operator",
                        "finding affects the payments service"
                );

        var first = registry.revise(FINDING_ID, 0, linked);
        require(first.status() == FindingBusinessServiceLinkRegistry.MutationStatus.UPDATED,
                "first business-service association must append revision 1");
        require(first.current().revision() == 1, "business-service revision 1 expected");
        require(first.current().recordedAt().equals(T7), "business-service registry clock must be exact");
        require("payments".equals(first.current().businessService()),
                "business service must be normalized");
        UUID firstEventId = first.current().eventId();

        var replay = registry.revise(FINDING_ID, 0, linked);
        require(replay.status() == FindingBusinessServiceLinkRegistry.MutationStatus.REPLAYED,
                "exact business-service retry must replay");
        require(replay.current().eventId().equals(firstEventId),
                "business-service replay must retain original event");

        var conflict = registry.revise(
                FINDING_ID,
                0,
                FindingBusinessServiceLink.ChangeDraft.unlinked(
                        "PAYMENTS",
                        "live-test-operator",
                        "stale expected revision"
                )
        );
        require(conflict.status() == FindingBusinessServiceLinkRegistry.MutationStatus.REVISION_CONFLICT,
                "stale business-service mutation must conflict");
        require(conflict.current().eventId().equals(firstEventId),
                "business-service conflict must return current event");

        var current = registry.current(FINDING_ID, "PAYMENTS");
        require(current.findingExists(), "business-service current lookup must resolve Finding");
        require(current.currentOptional().orElseThrow().eventId().equals(firstEventId),
                "business-service current lookup must resolve revision 1");
        require(registry.history(FINDING_ID, "payments", 10, null)
                        .orElseThrow().events().size() == 1,
                "business-service replay must not append history");
        require(registry.listCurrent(FINDING_ID, 10, null).orElseThrow().links().size() == 1,
                "business-service current list must expose one logical stream");

        var missing = registry.revise(MISSING_FINDING_ID, 0, linked);
        require(missing.status() == FindingBusinessServiceLinkRegistry.MutationStatus.FINDING_NOT_FOUND,
                "missing Finding must not create business-service history");

        PostgresFindingBusinessServiceLinkRegistry later =
                new PostgresFindingBusinessServiceLinkRegistry(
                        connections,
                        schemaVersion,
                        Clock.fixed(T8, ZoneOffset.UTC)
                );
        var unlink = later.revise(
                FINDING_ID,
                1,
                FindingBusinessServiceLink.ChangeDraft.unlinked(
                        "payments",
                        "live-test-operator",
                        "explicit customer unlink"
                )
        );
        require(unlink.status() == FindingBusinessServiceLinkRegistry.MutationStatus.UPDATED,
                "business-service unlink must append revision 2");
        require(unlink.current().revision() == 2, "business-service revision 2 expected");
        require(unlink.current().linkStatus() == FindingBusinessServiceLink.LinkStatus.UNLINKED,
                "business-service current state must preserve explicit UNLINKED");
        require(later.history(FINDING_ID, "payments", 10, null)
                        .orElseThrow().events().size() == 2,
                "business-service history must preserve both revisions");
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
