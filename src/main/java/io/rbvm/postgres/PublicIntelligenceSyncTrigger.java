package io.rbvm.postgres;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

/** Manual/scheduled trigger boundary for one exact provider source synchronization job. */
@FunctionalInterface
public interface PublicIntelligenceSyncTrigger {
    record Submission(
            UUID jobId,
            PostgresPublicIntelligenceStore.Provider provider,
            String nvdFeed,
            String status,
            String stage,
            Instant startedAt
    ) {
    }

    Submission submit(
            PostgresPublicIntelligenceStore.Provider provider,
            String nvdFeed,
            PostgresPublicIntelligenceSyncJobStore.TriggerSource triggerSource
    ) throws IOException;
}
