package io.rbvm.postgres;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Live PostgreSQL proof for V30 global local-public-intelligence source mirroring. */
public final class PostgresV30PublicIntelligenceStoreLiveSelfTest {
    private PostgresV30PublicIntelligenceStoreLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        PostgresPublicIntelligenceStore store = new PostgresPublicIntelligenceStore(connections, true);
        require(store.schemaVersion() >= 30, "public-intelligence live proof requires schema 30+");

        Instant t0 = Instant.parse("2026-08-24T04:00:00Z");
        String cveOne = "CVE-2099-90001";
        String cveTwo = "CVE-2099-90002";

        PostgresPublicIntelligenceStore.SourceDescriptor nvdBootstrap = source(
                PostgresPublicIntelligenceStore.Provider.NVD,
                "https://nvd.nist.gov/vuln/data-feeds",
                "bootstrap-2099",
                "a".repeat(64),
                t0.plusSeconds(30),
                t0.plusSeconds(60));
        PostgresPublicIntelligenceStore.BeginResult first = store.beginOrReplay(
                nvdBootstrap,
                PostgresPublicIntelligenceStore.SyncMode.BOOTSTRAP,
                t0);
        require(!first.replayed(), "first exact NVD source must create a STAGING run");
        require(first.status() == PostgresPublicIntelligenceStore.SyncStatus.STAGING,
                "new source run must be STAGING");

        PostgresPublicIntelligenceStore.AppendResult append = store.appendRecords(
                first.runId(),
                PostgresPublicIntelligenceStore.Provider.NVD,
                List.of(
                        active(cveOne, 1, t0.plusSeconds(30), t0.plusSeconds(60)),
                        active(cveTwo, 1, t0.plusSeconds(30), t0.plusSeconds(60))
                ));
        require(append.insertedRecords() == 2 && append.replayedRecords() == 0,
                "first append must persist both records");

        Map<String, Map<PostgresPublicIntelligenceStore.Provider,
                PostgresPublicIntelligenceStore.CurrentRecord>> beforeComplete =
                store.lookupCurrent(Set.of(cveOne, cveTwo));
        require(beforeComplete.isEmpty(), "STAGING source records must never be current");

        PostgresPublicIntelligenceStore.CompletionResult completed = store.completeRun(
                first.runId(),
                PostgresPublicIntelligenceStore.Provider.NVD,
                2,
                t0.plusSeconds(90));
        require(!completed.replayed() && completed.recordCount() == 2,
                "complete transition must verify exact record count");

        Map<String, Map<PostgresPublicIntelligenceStore.Provider,
                PostgresPublicIntelligenceStore.CurrentRecord>> initial =
                store.lookupCurrent(Set.of(cveOne, cveTwo));
        require(initial.size() == 2, "both NVD records must be visible after COMPLETE");
        require(initial.get(cveOne).get(PostgresPublicIntelligenceStore.Provider.NVD)
                        .payloadJson().contains("\"version\": 1"),
                "local lookup must expose stored NVD source JSON");

        PostgresPublicIntelligenceStore.BeginResult replay = store.beginOrReplay(
                nvdBootstrap,
                PostgresPublicIntelligenceStore.SyncMode.BOOTSTRAP,
                t0.plusSeconds(10));
        require(replay.replayed() && replay.runId().equals(first.runId()),
                "exact completed source SHA must replay the same immutable run");
        require(replay.status() == PostgresPublicIntelligenceStore.SyncStatus.COMPLETE,
                "exact source replay must expose terminal state");

        PostgresPublicIntelligenceStore.SourceDescriptor nvdDelta = source(
                PostgresPublicIntelligenceStore.Provider.NVD,
                "https://nvd.nist.gov/vuln/data-feeds",
                "modified-2099-08-24",
                "b".repeat(64),
                t0.plusSeconds(100),
                t0.plusSeconds(120));
        PostgresPublicIntelligenceStore.BeginResult delta = store.beginOrReplay(
                nvdDelta,
                PostgresPublicIntelligenceStore.SyncMode.INCREMENTAL,
                t0.plusSeconds(95));
        store.appendRecords(
                delta.runId(),
                PostgresPublicIntelligenceStore.Provider.NVD,
                List.of(
                        active(cveOne, 2, t0.plusSeconds(100), t0.plusSeconds(120)),
                        tombstone(cveTwo, t0.plusSeconds(100), t0.plusSeconds(120))
                ));
        store.completeRun(
                delta.runId(),
                PostgresPublicIntelligenceStore.Provider.NVD,
                2,
                t0.plusSeconds(130));

        Map<String, Map<PostgresPublicIntelligenceStore.Provider,
                PostgresPublicIntelligenceStore.CurrentRecord>> afterDelta =
                store.lookupCurrent(Set.of(cveOne, cveTwo));
        require(afterDelta.containsKey(cveOne), "newer NVD version must remain current");
        require(afterDelta.get(cveOne).get(PostgresPublicIntelligenceStore.Provider.NVD)
                        .payloadJson().contains("\"version\": 2"),
                "newer complete NVD record must replace older current source state");
        require(!afterDelta.containsKey(cveTwo),
                "newer COMPLETE TOMBSTONE must suppress, not resurrect, older provider state");

        PostgresPublicIntelligenceStore.SourceDescriptor epss = source(
                PostgresPublicIntelligenceStore.Provider.FIRST_EPSS,
                "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
                "2026-08-24",
                "c".repeat(64),
                t0.plusSeconds(140),
                t0.plusSeconds(150));
        PostgresPublicIntelligenceStore.BeginResult epssRun = store.beginOrReplay(
                epss,
                PostgresPublicIntelligenceStore.SyncMode.BOOTSTRAP,
                t0.plusSeconds(135));
        store.appendRecords(
                epssRun.runId(),
                PostgresPublicIntelligenceStore.Provider.FIRST_EPSS,
                List.of(new PostgresPublicIntelligenceStore.RecordVersion(
                        cveOne,
                        PostgresPublicIntelligenceStore.RecordState.ACTIVE,
                        null,
                        t0.plusSeconds(140),
                        "{\"cve\":\"" + cveOne + "\",\"epss\":\"0.42\"}",
                        t0.plusSeconds(150))));
        store.completeRun(
                epssRun.runId(),
                PostgresPublicIntelligenceStore.Provider.FIRST_EPSS,
                1,
                t0.plusSeconds(160));

        Map<String, Map<PostgresPublicIntelligenceStore.Provider,
                PostgresPublicIntelligenceStore.CurrentRecord>> multiProvider =
                store.lookupCurrent(Set.of(cveOne));
        require(multiProvider.get(cveOne).size() == 2,
                "one CVE must retain independent current NVD and FIRST EPSS records");

        boolean updateBlocked = false;
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     UPDATE rbvm.public_intelligence_record
                     SET payload_json = '{"mutated":true}'::jsonb
                     WHERE sync_run_id = ? AND cve_id = ?
                     """)) {
            statement.setObject(1, first.runId());
            statement.setString(2, cveOne);
            statement.executeUpdate();
        } catch (SQLException expected) {
            updateBlocked = expected.getMessage().contains("append-only");
        }
        require(updateBlocked, "public-intelligence record history must be append-only");

        boolean lateInsertBlocked = false;
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     INSERT INTO rbvm.public_intelligence_record(
                         sync_run_id, provider, cve_id, record_state,
                         payload_json, record_sha256, observed_at
                     ) VALUES (?, 'NVD', 'CVE-2099-90003', 'ACTIVE',
                               '{}'::jsonb, ?, ?)
                     """)) {
            statement.setObject(1, first.runId());
            statement.setString(2, "d".repeat(64));
            statement.setTimestamp(3, Timestamp.from(t0.plusSeconds(200)));
            statement.executeUpdate();
        } catch (SQLException expected) {
            lateInsertBlocked = expected.getMessage().contains("STAGING");
        }
        require(lateInsertBlocked, "COMPLETE sync runs must reject late record insertion");

        PostgresPublicIntelligenceStore.SourceDescriptor retryable = source(
                PostgresPublicIntelligenceStore.Provider.CVE_PROGRAM,
                "https://github.com/CVEProject/cvelistV5",
                "failed-source",
                "e".repeat(64),
                t0.plusSeconds(210),
                t0.plusSeconds(220));
        PostgresPublicIntelligenceStore.BeginResult failed = store.beginOrReplay(
                retryable,
                PostgresPublicIntelligenceStore.SyncMode.INCREMENTAL,
                t0.plusSeconds(205));
        store.failRun(
                failed.runId(),
                PostgresPublicIntelligenceStore.Provider.CVE_PROGRAM,
                "SOURCE_FETCH_FAILED",
                "synthetic provider failure",
                t0.plusSeconds(230));
        PostgresPublicIntelligenceStore.BeginResult retry = store.beginOrReplay(
                retryable,
                PostgresPublicIntelligenceStore.SyncMode.INCREMENTAL,
                t0.plusSeconds(215));
        require(!retry.replayed() && !retry.runId().equals(failed.runId()),
                "FAILED source SHA must remain retryable with a fresh STAGING run");
        store.failRun(
                retry.runId(),
                PostgresPublicIntelligenceStore.Provider.CVE_PROGRAM,
                "SOURCE_FETCH_FAILED",
                "synthetic retry cleanup",
                t0.plusSeconds(240));

        System.out.println("PostgresV30PublicIntelligenceStoreLiveSelfTest: PASS schema="
                + store.schemaVersion());
    }

    private static PostgresPublicIntelligenceStore.SourceDescriptor source(
            PostgresPublicIntelligenceStore.Provider provider,
            String uri,
            String version,
            String sha,
            Instant publishedAt,
            Instant observedAt
    ) {
        return new PostgresPublicIntelligenceStore.SourceDescriptor(
                provider, uri, version, sha, publishedAt, observedAt);
    }

    private static PostgresPublicIntelligenceStore.RecordVersion active(
            String cve,
            int version,
            Instant modifiedAt,
            Instant observedAt
    ) {
        return new PostgresPublicIntelligenceStore.RecordVersion(
                cve,
                PostgresPublicIntelligenceStore.RecordState.ACTIVE,
                modifiedAt,
                modifiedAt.minusSeconds(10),
                "{\"id\":\"" + cve + "\",\"version\":" + version + "}",
                observedAt);
    }

    private static PostgresPublicIntelligenceStore.RecordVersion tombstone(
            String cve,
            Instant modifiedAt,
            Instant observedAt
    ) {
        return new PostgresPublicIntelligenceStore.RecordVersion(
                cve,
                PostgresPublicIntelligenceStore.RecordState.TOMBSTONE,
                modifiedAt,
                null,
                null,
                observedAt);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
