package io.rbvm.postgres;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Runs explicit startup and fixed-delay public-intelligence automation without hidden defaults. */
public final class PublicIntelligenceAutomationController implements AutoCloseable {
    private final PublicIntelligenceAutomationSettings settings;
    private final PublicIntelligenceAutomationPlanExecutor plans;
    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean started = new AtomicBoolean();

    public PublicIntelligenceAutomationController(
            PublicIntelligenceAutomationSettings settings,
            PublicIntelligenceAutomationPlanExecutor plans
    ) {
        this.settings = Objects.requireNonNull(settings, "settings");
        this.plans = Objects.requireNonNull(plans, "plans");
        int threads = Math.min(
                4,
                Math.max(
                        1,
                        settings.scheduledRefreshIntervals().size()
                                + (settings.nvdBootstrapOnStartup() ? 1 : 0)
                                + Math.min(1, settings.startupRefreshProviders().size())));
        this.scheduler = Executors.newScheduledThreadPool(threads, runnable -> {
            Thread thread = new Thread(runnable, "rbvm-public-intelligence-automation");
            thread.setDaemon(true);
            return thread;
        });
    }

    /** Start configured automation exactly once. Construction itself performs no source I/O. */
    public void start() {
        if (!settings.enabled() || !started.compareAndSet(false, true)) return;

        if (settings.nvdBootstrapOnStartup()) {
            scheduler.execute(() -> safeRun(
                    "startup NVD bootstrap",
                    plans::runNvdBootstrap));
        }

        for (PostgresPublicIntelligenceStore.Provider provider
                : settings.startupRefreshProviders()) {
            if (provider == PostgresPublicIntelligenceStore.Provider.NVD
                    && settings.nvdBootstrapOnStartup()) {
                continue;
            }
            scheduler.execute(() -> safeRun(
                    "startup refresh " + provider.name(),
                    () -> plans.runRefresh(
                            provider,
                            PostgresPublicIntelligenceSyncJobStore.TriggerSource.STARTUP)));
        }

        for (Map.Entry<PostgresPublicIntelligenceStore.Provider, Duration> entry
                : settings.scheduledRefreshIntervals().entrySet()) {
            PostgresPublicIntelligenceStore.Provider provider = entry.getKey();
            long delay = entry.getValue().getSeconds();
            scheduler.scheduleWithFixedDelay(
                    () -> safeRun(
                            "scheduled refresh " + provider.name(),
                            () -> plans.runRefresh(
                                    provider,
                                    PostgresPublicIntelligenceSyncJobStore.TriggerSource.SCHEDULED)),
                    delay,
                    delay,
                    TimeUnit.SECONDS);
        }
    }

    private static void safeRun(String operation, CheckedOperation action) {
        try {
            action.run();
        } catch (PublicIntelligenceSyncCoordinator.AlreadyRunningException exception) {
            System.err.println("Public intelligence automation skipped overlap: " + operation);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } catch (IOException | RuntimeException exception) {
            System.err.println(
                    "Public intelligence automation failed: " + operation + " ["
                            + exception.getClass().getSimpleName() + ']');
        }
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
        boolean interrupted = false;
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) scheduler.shutdownNow();
        } catch (InterruptedException exception) {
            interrupted = true;
            scheduler.shutdownNow();
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    @FunctionalInterface
    private interface CheckedOperation {
        void run() throws IOException, InterruptedException;
    }
}
