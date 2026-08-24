package io.rbvm.postgres;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Dependency-free proof for explicit automation settings and exact NVD bootstrap sequencing. */
public final class PublicIntelligenceAutomationSelfTest {
    private PublicIntelligenceAutomationSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        settingsAreOptInAndBounded();
        nvdBootstrapResumesMissingYearsInOrder();
        failedAnnualStopsBootstrapFailClosed();
        refreshUsesExactProviderScope();
        System.out.println("PublicIntelligenceAutomationSelfTest: PASS");
    }

    private static void settingsAreOptInAndBounded() {
        PublicIntelligenceAutomationSettings disabled =
                PublicIntelligenceAutomationSettings.fromEnvironment(Map.of());
        require(!disabled.enabled(), "automation must be disabled by default");

        Map<String, String> environment = Map.of(
                "RBVM_INTELLIGENCE_NVD_BOOTSTRAP_ON_STARTUP", "true",
                "RBVM_INTELLIGENCE_STARTUP_REFRESH_PROVIDERS", "CISA_KEV,FIRST_EPSS",
                "RBVM_INTELLIGENCE_SCHEDULE_NVD_SECONDS", "3600",
                "RBVM_INTELLIGENCE_SCHEDULE_CISA_KEV_SECONDS", "86400");
        PublicIntelligenceAutomationSettings configured =
                PublicIntelligenceAutomationSettings.fromEnvironment(environment);
        require(configured.enabled(), "explicit automation configuration must enable runtime");
        require(configured.nvdBootstrapOnStartup(), "explicit NVD startup bootstrap must be retained");
        require(configured.startupRefreshProviders().equals(Set.of(
                        PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                        PostgresPublicIntelligenceStore.Provider.FIRST_EPSS)),
                "startup providers must be exact and explicit");
        require(Duration.ofHours(1).equals(configured.scheduledRefreshIntervals().get(
                        PostgresPublicIntelligenceStore.Provider.NVD)),
                "NVD scheduled interval must retain exact configured duration");

        boolean tooFrequentRejected = false;
        try {
            PublicIntelligenceAutomationSettings.fromEnvironment(Map.of(
                    "RBVM_INTELLIGENCE_SCHEDULE_FIRST_EPSS_SECONDS", "3599"));
        } catch (IllegalArgumentException expected) {
            tooFrequentRejected = true;
        }
        require(tooFrequentRejected, "sub-hour automatic refresh cadence must be rejected");
    }

    private static void nvdBootstrapResumesMissingYearsInOrder() throws Exception {
        FakeRuntime fake = new FakeRuntime(null);
        PublicIntelligenceAutomationPlanExecutor plans =
                new PublicIntelligenceAutomationPlanExecutor(
                        fake,
                        fake,
                        () -> Set.of(2002, 2004),
                        () -> 2005);
        plans.runNvdBootstrap();
        require(fake.submissions.equals(List.of(
                        "NVD:2003:STARTUP",
                        "NVD:2005:STARTUP",
                        "NVD:modified:STARTUP")),
                "NVD bootstrap must run only missing annual feeds in order, then modified");
    }

    private static void failedAnnualStopsBootstrapFailClosed() throws Exception {
        FakeRuntime fake = new FakeRuntime("2003");
        PublicIntelligenceAutomationPlanExecutor plans =
                new PublicIntelligenceAutomationPlanExecutor(
                        fake,
                        fake,
                        () -> Set.of(2002),
                        () -> 2004);
        boolean failed = false;
        try {
            plans.runNvdBootstrap();
        } catch (IOException expected) {
            failed = expected.getMessage().contains("BOOTSTRAP_TEST_FAILURE");
        }
        require(failed, "failed annual NVD source must stop bootstrap with stable V31 error code");
        require(fake.submissions.equals(List.of("NVD:2003:STARTUP")),
                "bootstrap must not skip past a failed year or run modified tail");
    }

    private static void refreshUsesExactProviderScope() throws Exception {
        FakeRuntime fake = new FakeRuntime(null);
        PublicIntelligenceAutomationPlanExecutor plans =
                new PublicIntelligenceAutomationPlanExecutor(
                        fake,
                        fake,
                        Set::of,
                        () -> 2002);
        plans.runRefresh(
                PostgresPublicIntelligenceStore.Provider.NVD,
                PostgresPublicIntelligenceSyncJobStore.TriggerSource.SCHEDULED);
        plans.runRefresh(
                PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                PostgresPublicIntelligenceSyncJobStore.TriggerSource.STARTUP);
        require(fake.submissions.equals(List.of(
                        "NVD:modified:SCHEDULED",
                        "CISA_KEV:null:STARTUP")),
                "refresh must use NVD modified and no synthetic feed for complete-snapshot providers");
    }

    private static final class FakeRuntime
            implements PublicIntelligenceSyncTrigger, PublicIntelligenceSyncCompletionReader {
        private final String failingFeed;
        private final List<String> submissions = new ArrayList<>();
        private final Map<UUID, Completion> completions = new HashMap<>();
        private long sequence;

        private FakeRuntime(String failingFeed) {
            this.failingFeed = failingFeed;
        }

        @Override
        public Submission submit(
                PostgresPublicIntelligenceStore.Provider provider,
                String nvdFeed,
                PostgresPublicIntelligenceSyncJobStore.TriggerSource triggerSource
        ) {
            submissions.add(provider.name() + ':' + nvdFeed + ':' + triggerSource.name());
            UUID id = new UUID(0L, ++sequence);
            boolean fail = failingFeed != null && failingFeed.equals(nvdFeed);
            completions.put(
                    id,
                    new Completion(
                            fail
                                    ? PostgresPublicIntelligenceSyncJobStore.Status.FAILED
                                    : PostgresPublicIntelligenceSyncJobStore.Status.COMPLETE,
                            fail ? "BOOTSTRAP_TEST_FAILURE" : null));
            return new Submission(
                    id,
                    provider,
                    nvdFeed,
                    "RUNNING",
                    "ACQUIRING",
                    Instant.parse("2026-08-24T08:00:00Z"));
        }

        @Override
        public Completion read(UUID jobId, PostgresPublicIntelligenceStore.Provider provider) {
            Completion completion = completions.get(jobId);
            if (completion == null) throw new IllegalArgumentException("unknown test job");
            return completion;
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
