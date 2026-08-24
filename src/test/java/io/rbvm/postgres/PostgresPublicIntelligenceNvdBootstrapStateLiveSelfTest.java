package io.rbvm.postgres;

import java.time.Instant;
import java.util.Set;

/** Live PostgreSQL proof that NVD bootstrap coverage derives only from completed annual V30 runs. */
public final class PostgresPublicIntelligenceNvdBootstrapStateLiveSelfTest {
    private PostgresPublicIntelligenceNvdBootstrapStateLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        PostgresPublicIntelligenceStore sources = new PostgresPublicIntelligenceStore(connections, true);
        PostgresPublicIntelligenceNvdBootstrapStateReader reader =
                new PostgresPublicIntelligenceNvdBootstrapStateReader(connections);

        Instant t0 = Instant.parse("2026-08-24T08:30:00Z");
        var annual2002 = sources.beginOrReplay(
                new PostgresPublicIntelligenceStore.SourceDescriptor(
                        PostgresPublicIntelligenceStore.Provider.NVD,
                        "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2002.json.gz",
                        "automation-live-2002",
                        "1".repeat(64),
                        null,
                        t0),
                PostgresPublicIntelligenceStore.SyncMode.BOOTSTRAP,
                t0.minusSeconds(1));
        sources.completeRun(
                annual2002.runId(),
                PostgresPublicIntelligenceStore.Provider.NVD,
                0,
                t0.plusSeconds(1));

        var failed2003 = sources.beginOrReplay(
                new PostgresPublicIntelligenceStore.SourceDescriptor(
                        PostgresPublicIntelligenceStore.Provider.NVD,
                        "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2003.json.gz",
                        "automation-live-2003",
                        "2".repeat(64),
                        null,
                        t0.plusSeconds(2)),
                PostgresPublicIntelligenceStore.SyncMode.BOOTSTRAP,
                t0.plusSeconds(1));
        sources.failRun(
                failed2003.runId(),
                PostgresPublicIntelligenceStore.Provider.NVD,
                "SYNTHETIC_TEST_FAILURE",
                "synthetic failed annual source",
                t0.plusSeconds(3));

        var modified = sources.beginOrReplay(
                new PostgresPublicIntelligenceStore.SourceDescriptor(
                        PostgresPublicIntelligenceStore.Provider.NVD,
                        "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
                        "automation-live-modified",
                        "3".repeat(64),
                        null,
                        t0.plusSeconds(4)),
                PostgresPublicIntelligenceStore.SyncMode.INCREMENTAL,
                t0.plusSeconds(3));
        sources.completeRun(
                modified.runId(),
                PostgresPublicIntelligenceStore.Provider.NVD,
                0,
                t0.plusSeconds(5));

        Set<Integer> years = reader.completedAnnualYears();
        require(years.contains(2002), "completed exact annual NVD run must count toward bootstrap");
        require(!years.contains(2003), "failed annual NVD run must not count toward bootstrap");
        require(!years.contains(0), "modified NVD source must never masquerade as annual coverage");

        System.out.println(
                "PostgresPublicIntelligenceNvdBootstrapStateLiveSelfTest: PASS"
                        + " completed_annual=PASS failed_annual_ignored=PASS modified_ignored=PASS");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
