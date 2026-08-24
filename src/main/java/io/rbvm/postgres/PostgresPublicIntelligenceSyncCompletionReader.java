package io.rbvm.postgres;

import java.io.IOException;
import java.util.Objects;
import java.util.UUID;

/** PostgreSQL-backed completion reader for exact V31 jobs. */
public final class PostgresPublicIntelligenceSyncCompletionReader
        implements PublicIntelligenceSyncCompletionReader {
    private final PostgresPublicIntelligenceSyncJobStore jobs;

    public PostgresPublicIntelligenceSyncCompletionReader(
            PostgresPublicIntelligenceSyncJobStore jobs
    ) {
        this.jobs = Objects.requireNonNull(jobs, "jobs");
    }

    @Override
    public Completion read(
            UUID jobId,
            PostgresPublicIntelligenceStore.Provider provider
    ) throws IOException {
        PostgresPublicIntelligenceSyncJobStore.Job job = jobs.requireJob(jobId, provider);
        return new Completion(job.status(), job.errorCode());
    }
}
