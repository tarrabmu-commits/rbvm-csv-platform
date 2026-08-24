package io.rbvm.postgres;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

/** Live PostgreSQL proof for V31 end-to-end public-intelligence sync jobs. */
public final class PostgresV31PublicIntelligenceSyncJobLiveSelfTest {
    private PostgresV31PublicIntelligenceSyncJobLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        PostgresPublicIntelligenceSyncJobStore jobs =
                new PostgresPublicIntelligenceSyncJobStore(connections, true);
        PostgresPublicIntelligenceStore sources =
                new PostgresPublicIntelligenceStore(connections, false);
        require(jobs.schemaVersion() >= 31, "sync-job live proof requires schema 31+");

        // Keep this source completion deterministically newer than any earlier live-test run
        // that may use wall-clock completion time in the same PostgreSQL workflow.
        Instant t0 = Instant.parse("2099-08-24T06:00:00Z");
        var provider = PostgresPublicIntelligenceStore.Provider.CISA_KEV;

        List<PublicIntelligenceStatusReader.ProviderStatus> initial = jobs.readStatus();
        require(initial.size() == 4, "status read must always expose all four providers");

        var failedAttempt = jobs.start(
                provider,
                PostgresPublicIntelligenceSyncJobStore.TriggerSource.SCHEDULED,
                t0);
        require(failedAttempt.stage() == PostgresPublicIntelligenceSyncJobStore.Stage.ACQUIRING,
                "new job must begin in ACQUIRING");

        boolean overlapBlocked = false;
        try {
            jobs.start(
                    provider,
                    PostgresPublicIntelligenceSyncJobStore.TriggerSource.MANUAL,
                    t0.plusSeconds(1));
        } catch (IOException expected) {
            overlapBlocked = true;
        }
        require(overlapBlocked, "only one RUNNING job per provider may exist");

        var failed = jobs.fail(
                failedAttempt.id(),
                provider,
                "SOURCE_FETCH_FAILED",
                "synthetic acquisition failure before V30 admission",
                t0.plusSeconds(10));
        require(failed.status() == PostgresPublicIntelligenceSyncJobStore.Status.FAILED,
                "pre-admission acquisition failure must persist as FAILED");
        require(failed.source() == null && failed.syncRunId() == null,
                "pre-admission failure must not invent source identity or V30 run identity");

        var afterFailure = status(jobs.readStatus(), provider);
        require("FAILED".equals(afterFailure.latestJobStatus()),
                "status view must expose the latest failed operational job");
        require("SOURCE_FETCH_FAILED".equals(afterFailure.latestJobErrorCode()),
                "status view must expose the acquisition failure code");

        var successfulAttempt = jobs.start(
                provider,
                PostgresPublicIntelligenceSyncJobStore.TriggerSource.MANUAL,
                t0.plusSeconds(20));
        var sourceIdentity = new PostgresPublicIntelligenceSyncJobStore.SourceIdentity(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "v31-live-2099",
                "a".repeat(64));
        var building = jobs.acquired(
                successfulAttempt.id(), provider, sourceIdentity, t0.plusSeconds(30));
        require(building.stage() == PostgresPublicIntelligenceSyncJobStore.Stage.BUILDING,
                "acquisition success must advance to BUILDING");
        var admitting = jobs.bundleBuilt(
                successfulAttempt.id(), provider, t0.plusSeconds(40));
        require(admitting.stage() == PostgresPublicIntelligenceSyncJobStore.Stage.ADMITTING,
                "bundle completion must advance to ADMITTING");

        boolean prematureCompleteBlocked = false;
        try {
            jobs.complete(successfulAttempt.id(), provider, t0.plusSeconds(45));
        } catch (IOException expected) {
            prematureCompleteBlocked = true;
        }
        require(prematureCompleteBlocked,
                "job must not complete before it is linked to a COMPLETE V30 run");

        PostgresPublicIntelligenceStore.SourceDescriptor descriptor =
                new PostgresPublicIntelligenceStore.SourceDescriptor(
                        provider,
                        sourceIdentity.sourceUri(),
                        sourceIdentity.sourceVersion(),
                        sourceIdentity.sourceSha256(),
                        t0.plusSeconds(25),
                        t0.plusSeconds(50));
        var run = sources.beginOrReplay(
                descriptor,
                PostgresPublicIntelligenceStore.SyncMode.BOOTSTRAP,
                t0.plusSeconds(24));
        String cve = "CVE-2099-91001";
        sources.appendRecords(
                run.runId(),
                provider,
                List.of(new PostgresPublicIntelligenceStore.RecordVersion(
                        cve,
                        PostgresPublicIntelligenceStore.RecordState.ACTIVE,
                        t0.plusSeconds(25),
                        t0.plusSeconds(24),
                        "{\"cveID\":\"" + cve + "\"}",
                        t0.plusSeconds(50))));

        jobs.linkSyncRun(
                successfulAttempt.id(), provider, run.runId(), t0.plusSeconds(55));
        boolean incompleteSourceRunBlocked = false;
        try {
            jobs.complete(successfulAttempt.id(), provider, t0.plusSeconds(56));
        } catch (IOException expected) {
            incompleteSourceRunBlocked = true;
        }
        require(incompleteSourceRunBlocked,
                "linked STAGING V30 run must not permit job completion");

        sources.completeRun(run.runId(), provider, 1, t0.plusSeconds(60));
        var complete = jobs.complete(
                successfulAttempt.id(), provider, t0.plusSeconds(65));
        require(complete.status() == PostgresPublicIntelligenceSyncJobStore.Status.COMPLETE,
                "job must complete after its linked V30 run is COMPLETE");
        require(run.runId().equals(complete.syncRunId()),
                "job must retain exact V30 source-run identity");

        var finalStatus = status(jobs.readStatus(), provider);
        require("COMPLETE".equals(finalStatus.latestJobStatus()),
                "latest operational job must be COMPLETE");
        require(run.runId().equals(finalStatus.latestJobSyncRunId()),
                "status must expose exact linked V30 run");
        require(run.runId().equals(finalStatus.latestSuccessId()),
                "status must independently expose the same last successful V30 source run");
        require(Long.valueOf(1).equals(finalStatus.latestSuccessRecordCount()),
                "status must expose last successful V30 record count");

        boolean terminalMutationBlocked = false;
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     UPDATE rbvm.public_intelligence_sync_job
                     SET updated_at = ?
                     WHERE id = ?
                     """)) {
            statement.setTimestamp(1, Timestamp.from(t0.plusSeconds(70)));
            statement.setObject(2, successfulAttempt.id());
            statement.executeUpdate();
        } catch (SQLException expected) {
            terminalMutationBlocked = expected.getMessage().contains("terminal");
        }
        require(terminalMutationBlocked, "terminal sync-job history must be immutable");

        var skipAttempt = jobs.start(
                PostgresPublicIntelligenceStore.Provider.CVE_PROGRAM,
                PostgresPublicIntelligenceSyncJobStore.TriggerSource.SYSTEM,
                t0.plusSeconds(80));
        boolean stageSkipBlocked = false;
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     UPDATE rbvm.public_intelligence_sync_job
                     SET stage = 'ADMITTING',
                         source_uri = 'https://github.com/CVEProject/cvelistV5',
                         source_version = 'skip',
                         source_sha256 = ?,
                         updated_at = ?
                     WHERE id = ?
                     """)) {
            statement.setString(1, "b".repeat(64));
            statement.setTimestamp(2, Timestamp.from(t0.plusSeconds(81)));
            statement.setObject(3, skipAttempt.id());
            statement.executeUpdate();
        } catch (SQLException expected) {
            stageSkipBlocked = expected.getMessage().contains("ACQUIRING");
        }
        require(stageSkipBlocked, "database guard must reject skipped lifecycle stages");
        jobs.fail(
                skipAttempt.id(),
                PostgresPublicIntelligenceStore.Provider.CVE_PROGRAM,
                "TEST_CLEANUP",
                "synthetic cleanup",
                t0.plusSeconds(82));

        System.out.println(
                "PostgresV31PublicIntelligenceSyncJobLiveSelfTest: PASS schema="
                        + jobs.schemaVersion()
                        + " pre_admission_failure=PASS overlap_guard=PASS"
                        + " v30_link=PASS terminal_immutable=PASS stage_guard=PASS");
    }

    private static PublicIntelligenceStatusReader.ProviderStatus status(
            List<PublicIntelligenceStatusReader.ProviderStatus> statuses,
            PostgresPublicIntelligenceStore.Provider provider
    ) {
        return statuses.stream()
                .filter(status -> status.provider() == provider)
                .findFirst()
                .orElseThrow();
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
