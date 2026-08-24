package io.rbvm.postgres;

import java.io.IOException;
import java.util.UUID;

/** Minimal read boundary used by automation to wait for one exact persisted V31 job. */
@FunctionalInterface
public interface PublicIntelligenceSyncCompletionReader {
    record Completion(
            PostgresPublicIntelligenceSyncJobStore.Status status,
            String errorCode
    ) {
        public Completion {
            if (status == null) throw new IllegalArgumentException("status is required");
        }

        public boolean terminal() {
            return status != PostgresPublicIntelligenceSyncJobStore.Status.RUNNING;
        }
    }

    Completion read(
            UUID jobId,
            PostgresPublicIntelligenceStore.Provider provider
    ) throws IOException;
}
