package io.rbvm.postgres;

import java.io.IOException;
import java.time.Year;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.IntSupplier;

/** Executes explicit automation plans while preserving one V31 job per exact source payload. */
public final class PublicIntelligenceAutomationPlanExecutor {
    private static final int NVD_FIRST_ANNUAL_YEAR = 2002;
    private static final long POLL_MILLIS = 250L;

    private final PublicIntelligenceSyncTrigger trigger;
    private final PublicIntelligenceSyncCompletionReader completionReader;
    private final PublicIntelligenceNvdBootstrapStateReader nvdBootstrapState;
    private final IntSupplier currentYear;

    public PublicIntelligenceAutomationPlanExecutor(
            PublicIntelligenceSyncTrigger trigger,
            PublicIntelligenceSyncCompletionReader completionReader,
            PublicIntelligenceNvdBootstrapStateReader nvdBootstrapState
    ) {
        this(trigger, completionReader, nvdBootstrapState,
                () -> Year.now(ZoneOffset.UTC).getValue());
    }

    PublicIntelligenceAutomationPlanExecutor(
            PublicIntelligenceSyncTrigger trigger,
            PublicIntelligenceSyncCompletionReader completionReader,
            PublicIntelligenceNvdBootstrapStateReader nvdBootstrapState,
            IntSupplier currentYear
    ) {
        this.trigger = Objects.requireNonNull(trigger, "trigger");
        this.completionReader = Objects.requireNonNull(completionReader, "completionReader");
        this.nvdBootstrapState = Objects.requireNonNull(nvdBootstrapState, "nvdBootstrapState");
        this.currentYear = Objects.requireNonNull(currentYear, "currentYear");
    }

    public void runRefresh(
            PostgresPublicIntelligenceStore.Provider provider,
            PostgresPublicIntelligenceSyncJobStore.TriggerSource triggerSource
    ) throws IOException, InterruptedException {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(triggerSource, "triggerSource");
        String feed = provider == PostgresPublicIntelligenceStore.Provider.NVD ? "modified" : null;
        runExact(provider, feed, triggerSource);
    }

    public void runNvdBootstrap() throws IOException, InterruptedException {
        Set<Integer> complete = nvdBootstrapState.completedAnnualYears();
        int endYear = currentYear.getAsInt();
        if (endYear < NVD_FIRST_ANNUAL_YEAR || endYear > 9999) {
            throw new IllegalStateException("current UTC year is outside the supported NVD range");
        }
        for (int year = NVD_FIRST_ANNUAL_YEAR; year <= endYear; year++) {
            if (!complete.contains(year)) {
                runExact(
                        PostgresPublicIntelligenceStore.Provider.NVD,
                        Integer.toString(year),
                        PostgresPublicIntelligenceSyncJobStore.TriggerSource.STARTUP);
            }
        }
        runExact(
                PostgresPublicIntelligenceStore.Provider.NVD,
                "modified",
                PostgresPublicIntelligenceSyncJobStore.TriggerSource.STARTUP);
    }

    private void runExact(
            PostgresPublicIntelligenceStore.Provider provider,
            String nvdFeed,
            PostgresPublicIntelligenceSyncJobStore.TriggerSource triggerSource
    ) throws IOException, InterruptedException {
        PublicIntelligenceSyncTrigger.Submission submission =
                trigger.submit(provider, nvdFeed, triggerSource);
        awaitComplete(submission.jobId(), provider);
    }

    private void awaitComplete(
            UUID jobId,
            PostgresPublicIntelligenceStore.Provider provider
    ) throws IOException, InterruptedException {
        while (true) {
            PublicIntelligenceSyncCompletionReader.Completion completion =
                    completionReader.read(jobId, provider);
            if (completion.status() == PostgresPublicIntelligenceSyncJobStore.Status.COMPLETE) return;
            if (completion.status() == PostgresPublicIntelligenceSyncJobStore.Status.FAILED) {
                String code = completion.errorCode() == null || completion.errorCode().isBlank()
                        ? "UNSPECIFIED"
                        : completion.errorCode();
                throw new IOException(
                        "public-intelligence automation job failed for " + provider.name()
                                + " [errorCode=" + code + ']');
            }
            Thread.sleep(POLL_MILLIS);
        }
    }
}
