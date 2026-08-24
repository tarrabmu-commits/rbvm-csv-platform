package io.rbvm.postgres;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Live PostgreSQL proof for the V31 -> source pipeline -> V30 orchestration path. */
public final class PostgresPublicIntelligenceSyncOrchestratorLiveSelfTest {
    private PostgresPublicIntelligenceSyncOrchestratorLiveSelfTest() {
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
        PostgresPublicIntelligenceCurrentCveReader current =
                new PostgresPublicIntelligenceCurrentCveReader(connections);
        require(jobs.schemaVersion() >= 31, "orchestrator live proof requires schema V31+");

        Path root = Files.createTempDirectory("rbvm-public-intelligence-orchestrator-live-");
        FakePipeline pipeline = new FakePipeline();
        try (PublicIntelligenceSyncCoordinator coordinator = new PublicIntelligenceSyncCoordinator(
                jobs, sources, current, pipeline, root, 2)) {

            var cisa1 = coordinator.submit(
                    PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                    null,
                    PostgresPublicIntelligenceSyncJobStore.TriggerSource.SYSTEM);
            var cisaJob1 = terminal(jobs, cisa1, Duration.ofSeconds(8));
            require(cisaJob1.status() == PostgresPublicIntelligenceSyncJobStore.Status.COMPLETE,
                    "first complete-snapshot orchestration must complete");
            require(cisaJob1.syncRunId() != null,
                    "completed orchestrator job must retain exact V30 run identity");
            Set<String> afterCisa1 =
                    current.currentCves(PostgresPublicIntelligenceStore.Provider.CISA_KEV);
            require(afterCisa1.contains("CVE-2099-92001"),
                    "first complete CISA snapshot must publish its test CVE as current");

            var cisa2 = coordinator.submit(
                    PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                    null,
                    PostgresPublicIntelligenceSyncJobStore.TriggerSource.SYSTEM);
            var cisaJob2 = terminal(jobs, cisa2, Duration.ofSeconds(8));
            require(cisaJob2.status() == PostgresPublicIntelligenceSyncJobStore.Status.COMPLETE,
                    "second complete-snapshot orchestration must complete");
            require(pipeline.secondCisaPrevious.contains("CVE-2099-92001"),
                    "complete-snapshot provider must receive its previous current test CVE");
            Set<String> afterCisa2 =
                    current.currentCves(PostgresPublicIntelligenceStore.Provider.CISA_KEV);
            require(!afterCisa2.contains("CVE-2099-92001")
                            && afterCisa2.contains("CVE-2099-92002"),
                    "explicit tombstone must suppress the removed CISA test CVE");

            var nvdYear = coordinator.submit(
                    PostgresPublicIntelligenceStore.Provider.NVD,
                    "2026",
                    PostgresPublicIntelligenceSyncJobStore.TriggerSource.SYSTEM);
            require(terminal(jobs, nvdYear, Duration.ofSeconds(8)).status()
                            == PostgresPublicIntelligenceSyncJobStore.Status.COMPLETE,
                    "NVD annual feed orchestration must complete");
            require(current.currentCves(PostgresPublicIntelligenceStore.Provider.NVD)
                            .contains("CVE-2099-93001"),
                    "NVD annual source must become current");

            var nvdModified = coordinator.submit(
                    PostgresPublicIntelligenceStore.Provider.NVD,
                    "modified",
                    PostgresPublicIntelligenceSyncJobStore.TriggerSource.SYSTEM);
            require(terminal(jobs, nvdModified, Duration.ofSeconds(8)).status()
                            == PostgresPublicIntelligenceSyncJobStore.Status.COMPLETE,
                    "NVD modified feed orchestration must complete");
            require(pipeline.nvdAlwaysReceivedEmptyPrevious,
                    "NVD partial/year feeds must never receive previous CVEs for tombstone inference");
            Set<String> nvdCurrent = current.currentCves(PostgresPublicIntelligenceStore.Provider.NVD);
            require(nvdCurrent.contains("CVE-2099-93001") && nvdCurrent.contains("CVE-2099-93002"),
                    "NVD modified absence must not tombstone an older current CVE");

            var failed = coordinator.submit(
                    PostgresPublicIntelligenceStore.Provider.FIRST_EPSS,
                    null,
                    PostgresPublicIntelligenceSyncJobStore.TriggerSource.SYSTEM);
            var failedJob = terminal(jobs, failed, Duration.ofSeconds(8));
            require(failedJob.status() == PostgresPublicIntelligenceSyncJobStore.Status.FAILED,
                    "pre-admission source failure must terminate the V31 job as FAILED");
            require(failedJob.syncRunId() == null,
                    "pre-admission source failure must not invent a V30 run identity");
            require("SOURCE_ACQUISITION_FAILED".equals(failedJob.errorCode()),
                    "acquisition failure must use the stable stage-specific error code");
        } finally {
            deleteTree(root);
        }

        System.out.println(
                "PostgresPublicIntelligenceSyncOrchestratorLiveSelfTest: PASS"
                        + " cisa_snapshot_tombstone=PASS nvd_no_absence_tombstone=PASS"
                        + " v30_v31_link=PASS pre_admission_failure=PASS");
    }

    private static PostgresPublicIntelligenceSyncJobStore.Job terminal(
            PostgresPublicIntelligenceSyncJobStore jobs,
            PublicIntelligenceSyncTrigger.Submission submission,
            Duration timeout
    ) throws Exception {
        Instant deadline = Instant.now().plus(timeout);
        while (Instant.now().isBefore(deadline)) {
            PostgresPublicIntelligenceSyncJobStore.Job job = jobs.requireJob(
                    submission.jobId(), submission.provider());
            if (job.status() != PostgresPublicIntelligenceSyncJobStore.Status.RUNNING) return job;
            Thread.sleep(25L);
        }
        throw new AssertionError("orchestrator job did not become terminal before timeout");
    }

    private static final class FakePipeline implements PublicIntelligenceSourcePipeline {
        private final Map<PostgresPublicIntelligenceStore.Provider, Integer> calls =
                new EnumMap<>(PostgresPublicIntelligenceStore.Provider.class);
        private final Map<String, Instant> observed = new HashMap<>();
        private Set<String> secondCisaPrevious = Set.of();
        private boolean nvdAlwaysReceivedEmptyPrevious = true;

        @Override
        public synchronized AcquiredSource acquire(
                PostgresPublicIntelligenceStore.Provider provider,
                String nvdFeed,
                Path workDirectory,
                Instant observedAt
        ) throws IOException {
            if (provider == PostgresPublicIntelligenceStore.Provider.FIRST_EPSS) {
                throw new IOException("synthetic acquisition failure before V30 admission");
            }
            int sequence = calls.merge(provider, 1, Integer::sum);
            Path acquisition = workDirectory.resolve("fake-acquisition");
            Files.createDirectory(acquisition);
            String version = provider.name().toLowerCase() + "-orchestrator-live-" + sequence;
            String sha = sha256(provider.name() + ":" + nvdFeed + ":" + sequence);
            observed.put(version, observedAt);
            return new AcquiredSource(
                    provider,
                    nvdFeed,
                    "https://example.test/rbvm/" + provider.name().toLowerCase() + "/" + sequence,
                    version,
                    sha,
                    acquisition);
        }

        @Override
        public synchronized Path buildBundle(
                AcquiredSource source,
                Set<String> previousCurrentCves,
                Path workDirectory
        ) throws IOException {
            int sequence = calls.get(source.provider());
            if (source.provider() == PostgresPublicIntelligenceStore.Provider.CISA_KEV
                    && sequence == 2) {
                secondCisaPrevious = Set.copyOf(previousCurrentCves);
            }
            if (source.provider() == PostgresPublicIntelligenceStore.Provider.NVD
                    && !previousCurrentCves.isEmpty()) {
                nvdAlwaysReceivedEmptyPrevious = false;
            }

            LinkedHashSet<String> active = new LinkedHashSet<>();
            if (source.provider() == PostgresPublicIntelligenceStore.Provider.CISA_KEV) {
                active.add(sequence == 1 ? "CVE-2099-92001" : "CVE-2099-92002");
            } else if (source.provider() == PostgresPublicIntelligenceStore.Provider.NVD) {
                active.add(sequence == 1 ? "CVE-2099-93001" : "CVE-2099-93002");
            } else {
                throw new IOException("unexpected fake provider");
            }

            Path bundle = workDirectory.resolve("bundle");
            Files.createDirectory(bundle);
            Path records = bundle.resolve("records.tsv");
            Instant time = observed.get(source.sourceVersion());
            List<String> lines = new ArrayList<>();
            lines.add("CVE_ID\tRecord_State\tSource_Modified_At\tSource_Published_At\tObserved_At\tPayload_Base64");
            for (String cve : active) {
                String payload = Base64.getEncoder().encodeToString(
                        ("{\"cve\":\"" + cve + "\",\"provider\":\""
                                + source.provider().name() + "\"}")
                                .getBytes(StandardCharsets.UTF_8));
                lines.add(cve + "\tACTIVE\t\t\t" + time + "\t" + payload);
            }
            if (source.provider() != PostgresPublicIntelligenceStore.Provider.NVD) {
                for (String old : previousCurrentCves) {
                    if (!active.contains(old)) {
                        lines.add(old + "\tTOMBSTONE\t\t\t" + time + "\t");
                    }
                }
            }
            Files.writeString(records, String.join("\n", lines) + "\n", StandardCharsets.UTF_8);

            String mode = source.provider() == PostgresPublicIntelligenceStore.Provider.NVD
                    && "modified".equals(source.nvdFeed())
                    ? "INCREMENTAL"
                    : "BOOTSTRAP";
            String manifest = """
                    artifactType=PUBLIC_INTELLIGENCE_SYNC_BUNDLE
                    schemaVersion=1
                    provider=%s
                    syncMode=%s
                    sourceUri=%s
                    sourceVersion=%s
                    sourceSha256=%s
                    sourcePublishedAt=
                    observedAt=%s
                    startedAt=%s
                    recordCount=%d
                    recordsSha256=%s
                    """.formatted(
                    source.provider().name(),
                    mode,
                    source.sourceUri(),
                    source.sourceVersion(),
                    source.sourceSha256(),
                    time,
                    time.minusSeconds(1),
                    lines.size() - 1,
                    sha256(records));
            Files.writeString(bundle.resolve("manifest.properties"), manifest, StandardCharsets.UTF_8);
            return bundle;
        }
    }

    private static String sha256(Path path) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = Files.readAllBytes(path);
            return java.util.HexFormat.of().formatHex(digest.digest(bytes));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of().formatHex(
                    digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static void deleteTree(Path root) throws IOException {
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
