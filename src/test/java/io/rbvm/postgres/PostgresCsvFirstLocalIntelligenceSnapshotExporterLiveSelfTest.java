package io.rbvm.postgres;

import io.rbvm.csv.CsvFirstLocalIntelligenceSnapshotExporter;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/** Live PostgreSQL proof for the CSV-first V30 local-intelligence export boundary. */
public final class PostgresCsvFirstLocalIntelligenceSnapshotExporterLiveSelfTest {
    private PostgresCsvFirstLocalIntelligenceSnapshotExporterLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        PostgresPublicIntelligenceStore store = new PostgresPublicIntelligenceStore(connections, true);
        PostgresPublicIntelligenceSyncJobStore status =
                new PostgresPublicIntelligenceSyncJobStore(connections, false);
        PostgresCisaKevCatalogValidationReader cisaValidation =
                new PostgresCisaKevCatalogValidationReader(connections);
        require(store.schemaVersion() >= 31, "CSV local-intelligence export proof requires schema 31+");

        Instant t0 = Instant.parse("2026-08-24T06:00:00Z");
        String listed = "CVE-2099-91001";
        String tombstoned = "CVE-2099-91002";
        String absent = "CVE-2099-91003";

        PostgresPublicIntelligenceStore.SourceDescriptor cisa = new PostgresPublicIntelligenceStore.SourceDescriptor(
                PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "2099.08.24",
                "1".repeat(64),
                t0.plusSeconds(30),
                t0.plusSeconds(60));
        PostgresPublicIntelligenceSyncJobStore.Job cisaJob = status.start(
                PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                PostgresPublicIntelligenceSyncJobStore.TriggerSource.SYSTEM,
                t0.minusSeconds(20));
        status.acquired(
                cisaJob.id(),
                PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                new PostgresPublicIntelligenceSyncJobStore.SourceIdentity(
                        cisa.sourceUri(), cisa.sourceVersion(), cisa.sourceSha256()),
                t0.minusSeconds(10));
        status.bundleBuilt(
                cisaJob.id(),
                PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                t0.minusSeconds(5));

        PostgresPublicIntelligenceStore.BeginResult cisaRun = store.beginOrReplay(
                cisa, PostgresPublicIntelligenceStore.SyncMode.BOOTSTRAP, t0);
        store.appendRecords(
                cisaRun.runId(),
                PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                List.of(new PostgresPublicIntelligenceStore.RecordVersion(
                        listed,
                        PostgresPublicIntelligenceStore.RecordState.ACTIVE,
                        null,
                        null,
                        "{\"cveID\":\"" + listed + "\",\"dateAdded\":\"2099-08-24\"}",
                        t0.plusSeconds(60))));
        store.completeRun(
                cisaRun.runId(),
                PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                1,
                t0.plusSeconds(90));
        status.linkSyncRun(
                cisaJob.id(),
                PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                cisaRun.runId(),
                t0.plusSeconds(95));
        status.complete(
                cisaJob.id(),
                PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                t0.plusSeconds(100));
        require(cisaValidation.isCompleteValidatedCatalog(cisaRun.runId()),
                "linked COMPLETE V31 CISA job must admit safe negative semantics");

        PostgresPublicIntelligenceStore.SourceDescriptor nvdBase = new PostgresPublicIntelligenceStore.SourceDescriptor(
                PostgresPublicIntelligenceStore.Provider.NVD,
                "https://nvd.nist.gov/vuln/data-feeds",
                "bootstrap-2099-export-proof",
                "2".repeat(64),
                t0.plusSeconds(110),
                t0.plusSeconds(120));
        PostgresPublicIntelligenceStore.BeginResult nvdBaseRun = store.beginOrReplay(
                nvdBase, PostgresPublicIntelligenceStore.SyncMode.BOOTSTRAP, t0.plusSeconds(105));
        store.appendRecords(
                nvdBaseRun.runId(),
                PostgresPublicIntelligenceStore.Provider.NVD,
                List.of(new PostgresPublicIntelligenceStore.RecordVersion(
                        tombstoned,
                        PostgresPublicIntelligenceStore.RecordState.ACTIVE,
                        t0.plusSeconds(110),
                        t0.plusSeconds(80),
                        "{\"id\":\"" + tombstoned + "\",\"vulnStatus\":\"Analyzed\"}",
                        t0.plusSeconds(120))));
        store.completeRun(
                nvdBaseRun.runId(),
                PostgresPublicIntelligenceStore.Provider.NVD,
                1,
                t0.plusSeconds(130));

        PostgresPublicIntelligenceStore.SourceDescriptor nvdDelta = new PostgresPublicIntelligenceStore.SourceDescriptor(
                PostgresPublicIntelligenceStore.Provider.NVD,
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "modified-2099-export-proof",
                "3".repeat(64),
                t0.plusSeconds(140),
                t0.plusSeconds(150));
        PostgresPublicIntelligenceStore.BeginResult nvdDeltaRun = store.beginOrReplay(
                nvdDelta, PostgresPublicIntelligenceStore.SyncMode.INCREMENTAL, t0.plusSeconds(135));
        store.appendRecords(
                nvdDeltaRun.runId(),
                PostgresPublicIntelligenceStore.Provider.NVD,
                List.of(new PostgresPublicIntelligenceStore.RecordVersion(
                        tombstoned,
                        PostgresPublicIntelligenceStore.RecordState.TOMBSTONE,
                        t0.plusSeconds(140),
                        null,
                        null,
                        t0.plusSeconds(150))));
        store.completeRun(
                nvdDeltaRun.runId(),
                PostgresPublicIntelligenceStore.Provider.NVD,
                1,
                t0.plusSeconds(160));
        require(!cisaValidation.isCompleteValidatedCatalog(nvdDeltaRun.runId()),
                "non-CISA V30 runs must never admit CISA negative semantics");

        Path root = Files.createTempDirectory("rbvm-csv-local-intel-live-");
        try {
            Path input = root.resolve("input.csv");
            Files.writeString(
                    input,
                    "CVE_ID,Finding\n"
                            + listed + ",listed\n"
                            + tombstoned + ",tombstoned\n"
                            + absent + ",absent\n"
                            + listed + ",duplicate-finding\n",
                    StandardCharsets.UTF_8);
            Path output = root.resolve("export");

            PostgresCsvFirstLocalIntelligenceSnapshotExporter exporter =
                    new PostgresCsvFirstLocalIntelligenceSnapshotExporter(store, status, cisaValidation);
            CsvFirstLocalIntelligenceSnapshotExporter.ExportSummary summary =
                    exporter.export(input, output);

            require(summary.uniqueCves() == 3,
                    "exporter must deduplicate CSV CVEs before local lookup");
            require(summary.providerRecords() == 1,
                    "only the active CISA record should survive current-state resolution");
            require(summary.cvesWithoutActiveProviderRecords() == 2,
                    "tombstoned and completely absent CVEs must have no active provider records");
            require(summary.providersWithSuccessfulSnapshot() >= 2,
                    "CISA and NVD successful provider state must be exported independently of current CVE rows");

            String records = Files.readString(output.resolve("records.tsv"), StandardCharsets.UTF_8);
            require(records.contains(listed + "\tCISA_KEV\t"),
                    "active CISA KEV record must be exported");
            require(!records.contains(tombstoned + "\tNVD\t"),
                    "newer NVD tombstone must suppress older active payload in CSV export");
            require(!records.contains(absent + "\t"),
                    "completely absent CVE must not fabricate provider records");

            String providers = Files.readString(output.resolve("provider-status.tsv"), StandardCharsets.UTF_8);
            require(providers.contains("CISA_KEV\ttrue\ttrue\t"),
                    "safe CISA negative semantics must require the linked COMPLETE V31 lifecycle");
            require(providers.contains("NVD\ttrue\tfalse\t"),
                    "non-CISA providers must never claim CISA-style safe negative absence");

            String requested = Files.readString(output.resolve("requested-cves.txt"), StandardCharsets.UTF_8);
            require(requested.indexOf(listed) < requested.indexOf(tombstoned)
                            && requested.indexOf(tombstoned) < requested.indexOf(absent),
                    "requested CVEs must be deterministic and sorted");
            require(!requested.contains("\n\n"),
                    "requested CVE export must not insert blank lines between entries");
        } finally {
            deleteTree(root);
        }

        System.out.println("PostgresCsvFirstLocalIntelligenceSnapshotExporterLiveSelfTest: PASS schema="
                + store.schemaVersion());
    }

    private static void deleteTree(Path directory) throws Exception {
        if (!Files.exists(directory)) return;
        try (var paths = Files.walk(directory)) {
            for (Path path : paths.sorted((left, right) -> right.getNameCount() - left.getNameCount()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
