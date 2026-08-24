package io.rbvm.postgres;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

/** Live PostgreSQL proof for PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1 admission and replay. */
public final class PostgresPublicIntelligenceSyncBundleLiveSelfTest {
    private PostgresPublicIntelligenceSyncBundleLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        PostgresPublicIntelligenceStore store = new PostgresPublicIntelligenceStore(connections, true);
        require(store.schemaVersion() >= 30, "bundle live proof requires schema 30+");

        Path root = Files.createTempDirectory("rbvm-public-intelligence-bundle-live-");
        try {
            Path bundle = root.resolve("bundle");
            Files.createDirectory(bundle);
            String cve = "CVE-2099-90101";
            String payload = "{\"cveID\":\"" + cve + "\",\"product\":\"bundle-live\"}";
            String encoded = Base64.getEncoder().encodeToString(
                    payload.getBytes(StandardCharsets.UTF_8));
            String records = "CVE_ID\tRecord_State\tSource_Modified_At\t"
                    + "Source_Published_At\tObserved_At\tPayload_Base64\n"
                    + cve + "\tACTIVE\t2026-08-24T05:00:00Z\t"
                    + "2026-08-24T04:59:00Z\t2026-08-24T05:01:00Z\t"
                    + encoded + "\n";
            Path recordsPath = bundle.resolve("records.tsv");
            Files.writeString(recordsPath, records, StandardCharsets.UTF_8);
            String recordsSha = sha256(Files.readAllBytes(recordsPath));

            String manifest = "artifactType=PUBLIC_INTELLIGENCE_SYNC_BUNDLE\n"
                    + "schemaVersion=1\n"
                    + "provider=CISA_KEV\n"
                    + "syncMode=BOOTSTRAP\n"
                    + "sourceUri=https://www.cisa.gov/sites/default/files/feeds/"
                    + "known_exploited_vulnerabilities.json\n"
                    + "sourceVersion=bundle-live-2099\n"
                    + "sourceSha256=" + "f".repeat(64) + "\n"
                    + "sourcePublishedAt=2026-08-24T05:00:00Z\n"
                    + "observedAt=2026-08-24T05:01:00Z\n"
                    + "startedAt=2026-08-24T05:01:00Z\n"
                    + "recordCount=1\n"
                    + "recordsSha256=" + recordsSha + "\n";
            Files.writeString(
                    bundle.resolve("manifest.properties"), manifest, StandardCharsets.UTF_8);

            PublicIntelligenceSyncBundleImporter.ValidatedBundle validated =
                    PublicIntelligenceSyncBundleImporter.validateBundle(bundle);
            PublicIntelligenceSyncBundleImporter.ImportSummary first =
                    PublicIntelligenceSyncBundleImporter.importBundle(store, validated);
            require("COMPLETE".equals(first.status()), "first bundle import must complete");
            require(first.inserted() == 1 && first.replayed() == 0,
                    "first bundle import must insert one record");

            Map<String, Map<PostgresPublicIntelligenceStore.Provider,
                    PostgresPublicIntelligenceStore.CurrentRecord>> current =
                    store.lookupCurrent(Set.of(cve));
            require(current.containsKey(cve), "completed bundle record must be current");
            PostgresPublicIntelligenceStore.CurrentRecord currentRecord =
                    current.get(cve).get(PostgresPublicIntelligenceStore.Provider.CISA_KEV);
            require(currentRecord != null, "CISA KEV provider record must be present");
            require(currentRecord.payloadJson().contains(cve)
                            && currentRecord.payloadJson().contains("bundle-live"),
                    "local lookup must preserve the bundle payload semantically");
            String expectedRecordSha = new PostgresPublicIntelligenceStore.RecordVersion(
                    cve,
                    PostgresPublicIntelligenceStore.RecordState.ACTIVE,
                    Instant.parse("2026-08-24T05:00:00Z"),
                    Instant.parse("2026-08-24T04:59:00Z"),
                    payload,
                    Instant.parse("2026-08-24T05:01:00Z"))
                    .recordSha256();
            require(currentRecord.recordSha256().equals(expectedRecordSha),
                    "record SHA must bind the exact canonical payload admitted from the bundle");

            PublicIntelligenceSyncBundleImporter.ImportSummary replay =
                    PublicIntelligenceSyncBundleImporter.importBundle(store, validated);
            require("REPLAYED_COMPLETE".equals(replay.status()),
                    "exact completed bundle must replay");
            require(replay.runId().equals(first.runId()),
                    "exact bundle replay must retain immutable run identity");

            Files.writeString(recordsPath, records + "\n", StandardCharsets.UTF_8);
            boolean tamperRejected = false;
            try {
                PublicIntelligenceSyncBundleImporter.validateBundle(bundle);
            } catch (java.io.IOException expected) {
                tamperRejected = expected.getMessage().contains("SHA-256");
            }
            require(tamperRejected,
                    "records mutation after manifest publication must fail before PostgreSQL admission");
        } finally {
            deleteRecursively(root);
        }

        System.out.println("PostgresPublicIntelligenceSyncBundleLiveSelfTest: PASS schema="
                + store.schemaVersion());
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void deleteRecursively(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
