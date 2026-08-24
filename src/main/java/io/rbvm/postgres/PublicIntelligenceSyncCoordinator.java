package io.rbvm.postgres;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.Comparator;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Executes one exact provider source refresh through acquisition, bundle construction, V30
 * admission, and the V31 job lifecycle.
 */
public final class PublicIntelligenceSyncCoordinator
        implements PublicIntelligenceSyncTrigger, AutoCloseable {
    private static final Pattern NVD_FEED = Pattern.compile("^(modified|20[0-9]{2})$");

    private final PostgresPublicIntelligenceSyncJobStore jobs;
    private final PostgresPublicIntelligenceStore sources;
    private final PublicIntelligenceCurrentCveReader currentCves;
    private final PublicIntelligenceSourcePipeline pipeline;
    private final Path workRoot;
    private final ExecutorService executor;

    public PublicIntelligenceSyncCoordinator(
            PostgresPublicIntelligenceSyncJobStore jobs,
            PostgresPublicIntelligenceStore sources,
            PublicIntelligenceCurrentCveReader currentCves,
            PublicIntelligenceSourcePipeline pipeline,
            Path workRoot,
            int workers
    ) throws IOException {
        this.jobs = Objects.requireNonNull(jobs, "jobs");
        this.sources = Objects.requireNonNull(sources, "sources");
        this.currentCves = Objects.requireNonNull(currentCves, "currentCves");
        this.pipeline = Objects.requireNonNull(pipeline, "pipeline");
        this.workRoot = Objects.requireNonNull(workRoot, "workRoot").toAbsolutePath().normalize();
        if (workers < 1 || workers > 4) {
            throw new IllegalArgumentException("public-intelligence sync workers must be between 1 and 4");
        }
        prepareRoot(this.workRoot);
        this.executor = Executors.newFixedThreadPool(workers, runnable -> {
            Thread thread = new Thread(runnable, "rbvm-public-intelligence-sync");
            thread.setDaemon(true);
            return thread;
        });
    }

    @Override
    public Submission submit(
            PostgresPublicIntelligenceStore.Provider provider,
            String nvdFeed,
            PostgresPublicIntelligenceSyncJobStore.TriggerSource triggerSource
    ) throws IOException {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(triggerSource, "triggerSource");
        String feed = canonicalFeed(provider, nvdFeed);
        Instant startedAt = Instant.now();
        PostgresPublicIntelligenceSyncJobStore.Job job;
        try {
            job = jobs.start(provider, triggerSource, startedAt);
        } catch (IOException exception) {
            if (exception.getMessage() != null && exception.getMessage().contains("SQLState=23505")) {
                throw new AlreadyRunningException(provider);
            }
            throw exception;
        }

        try {
            executor.execute(() -> run(job, feed));
        } catch (RejectedExecutionException exception) {
            try {
                jobs.fail(
                        job.id(),
                        provider,
                        "SYNC_EXECUTOR_REJECTED",
                        "public-intelligence synchronization executor is unavailable",
                        Instant.now());
            } catch (IOException failureTransition) {
                exception.addSuppressed(failureTransition);
            }
            throw new IOException("public-intelligence synchronization executor is unavailable", exception);
        }
        return new Submission(
                job.id(),
                provider,
                feed,
                job.status().name(),
                job.stage().name(),
                job.startedAt());
    }

    private void run(PostgresPublicIntelligenceSyncJobStore.Job job, String nvdFeed) {
        Path work = workRoot.resolve(job.id().toString()).normalize();
        String failureCode = "SOURCE_ACQUISITION_FAILED";
        try {
            if (!work.getParent().equals(workRoot)) {
                throw new IOException("public-intelligence job work path escaped the configured root");
            }
            Files.createDirectory(work);
            setOwnerOnly(work, true);

            PublicIntelligenceSourcePipeline.AcquiredSource acquired = pipeline.acquire(
                    job.provider(), nvdFeed, work, Instant.now());
            PostgresPublicIntelligenceSyncJobStore.SourceIdentity sourceIdentity =
                    new PostgresPublicIntelligenceSyncJobStore.SourceIdentity(
                            acquired.sourceUri(), acquired.sourceVersion(), acquired.sourceSha256());
            jobs.acquired(job.id(), job.provider(), sourceIdentity, Instant.now());

            failureCode = "SOURCE_BUNDLE_BUILD_FAILED";
            Set<String> previous = completeSnapshotProvider(job.provider())
                    ? currentCves.currentCves(job.provider())
                    : Set.of();
            Path bundlePath = pipeline.buildBundle(acquired, previous, work);
            PublicIntelligenceSyncBundleImporter.ValidatedBundle bundle =
                    PublicIntelligenceSyncBundleImporter.validateBundle(bundlePath);
            requireExactSource(job.provider(), sourceIdentity, bundle, nvdFeed);
            jobs.bundleBuilt(job.id(), job.provider(), Instant.now());

            failureCode = "SOURCE_ADMISSION_FAILED";
            PublicIntelligenceSyncBundleImporter.ImportSummary imported =
                    PublicIntelligenceSyncBundleImporter.importBundle(sources, bundle);
            jobs.linkSyncRun(job.id(), job.provider(), imported.runId(), Instant.now());
            jobs.complete(job.id(), job.provider(), Instant.now());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            fail(job, "SYNC_INTERRUPTED", exception);
        } catch (IOException | RuntimeException exception) {
            fail(job, failureCode, exception);
        } finally {
            try {
                deleteRecursively(work);
            } catch (IOException ignored) {
                // Workspace cleanup cannot change the already durable V30/V31 outcome.
            }
        }
    }

    private void fail(
            PostgresPublicIntelligenceSyncJobStore.Job job,
            String errorCode,
            Exception exception
    ) {
        try {
            PostgresPublicIntelligenceSyncJobStore.Job current = jobs.requireJob(job.id(), job.provider());
            if (current.status() == PostgresPublicIntelligenceSyncJobStore.Status.RUNNING) {
                jobs.fail(
                        job.id(),
                        job.provider(),
                        errorCode,
                        safeFailureDetail(exception),
                        Instant.now());
            }
        } catch (IOException | RuntimeException failureTransition) {
            exception.addSuppressed(failureTransition);
        }
    }

    private static void requireExactSource(
            PostgresPublicIntelligenceStore.Provider provider,
            PostgresPublicIntelligenceSyncJobStore.SourceIdentity acquired,
            PublicIntelligenceSyncBundleImporter.ValidatedBundle bundle,
            String nvdFeed
    ) throws IOException {
        if (bundle.provider() != provider
                || !acquired.sourceUri().equals(bundle.sourceUri())
                || !acquired.sourceVersion().equals(bundle.sourceVersion())
                || !acquired.sourceSha256().equals(bundle.sourceSha256())) {
            throw new IOException("public-intelligence bundle source identity diverged from acquisition");
        }
        PostgresPublicIntelligenceStore.SyncMode expectedMode =
                provider == PostgresPublicIntelligenceStore.Provider.NVD
                        && "modified".equals(nvdFeed)
                        ? PostgresPublicIntelligenceStore.SyncMode.INCREMENTAL
                        : PostgresPublicIntelligenceStore.SyncMode.BOOTSTRAP;
        if (bundle.syncMode() != expectedMode) {
            throw new IOException("public-intelligence bundle sync mode diverged from requested source scope");
        }
    }

    private static boolean completeSnapshotProvider(PostgresPublicIntelligenceStore.Provider provider) {
        return provider == PostgresPublicIntelligenceStore.Provider.FIRST_EPSS
                || provider == PostgresPublicIntelligenceStore.Provider.CISA_KEV
                || provider == PostgresPublicIntelligenceStore.Provider.CVE_PROGRAM;
    }

    private static String canonicalFeed(
            PostgresPublicIntelligenceStore.Provider provider,
            String requested
    ) {
        if (provider != PostgresPublicIntelligenceStore.Provider.NVD) {
            if (requested != null && !requested.isBlank()) {
                throw new IllegalArgumentException("nvdFeed is valid only for provider NVD");
            }
            return null;
        }
        String feed = requested == null || requested.isBlank() ? "modified" : requested.trim();
        if (!NVD_FEED.matcher(feed).matches()) {
            throw new IllegalArgumentException("NVD feed must be modified or a four-digit year");
        }
        if (!"modified".equals(feed)) {
            int year = Integer.parseInt(feed);
            int current = java.time.Year.now(java.time.ZoneOffset.UTC).getValue();
            if (year < 2002 || year > current) {
                throw new IllegalArgumentException("NVD year feed is outside the supported range");
            }
        }
        return feed;
    }

    private static String safeFailureDetail(Exception exception) {
        String message = exception.getMessage();
        String detail = exception.getClass().getSimpleName()
                + (message == null || message.isBlank() ? "" : ": " + message);
        detail = detail.replace('\r', ' ').replace('\n', ' ').replaceAll("\\s+", " ").trim();
        if (detail.length() > 768) detail = detail.substring(0, 768);
        return detail.isEmpty() ? "public-intelligence synchronization failed" : detail;
    }

    private static void prepareRoot(Path root) throws IOException {
        if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(root) || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("public-intelligence work root must be a non-symlink directory");
            }
        } else {
            Files.createDirectories(root);
        }
        setOwnerOnly(root, true);
    }

    private static void setOwnerOnly(Path path, boolean directory) {
        try {
            Files.setPosixFilePermissions(
                    path,
                    PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"));
        } catch (IOException | UnsupportedOperationException ignored) {
            // POSIX permissions are a hardening layer; non-POSIX filesystems use platform defaults.
        }
    }

    private static void deleteRecursively(Path root) throws IOException {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return;
        if (Files.isSymbolicLink(root)) {
            throw new IOException("refusing to recursively delete a symlinked intelligence work path");
        }
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    @Override
    public void close() {
        executor.shutdownNow();
        boolean interrupted = false;
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException exception) {
            interrupted = true;
            executor.shutdownNow();
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    public static final class AlreadyRunningException extends IOException {
        private static final long serialVersionUID = 1L;

        public AlreadyRunningException(PostgresPublicIntelligenceStore.Provider provider) {
            super("a public-intelligence synchronization job is already running for "
                    + provider.name().toLowerCase(Locale.ROOT));
        }
    }
}
