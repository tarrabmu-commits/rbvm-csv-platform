package io.rbvm.postgres;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Read boundary for the four-provider operational public-intelligence status. */
public interface PublicIntelligenceStatusReader {
    record ProviderStatus(
            PostgresPublicIntelligenceStore.Provider provider,
            UUID latestJobId,
            String latestJobTriggerSource,
            String latestJobStatus,
            String latestJobStage,
            Instant latestJobStartedAt,
            Instant latestJobUpdatedAt,
            Instant latestJobCompletedAt,
            String latestJobSourceUri,
            String latestJobSourceVersion,
            String latestJobSourceSha256,
            UUID latestJobSyncRunId,
            String latestJobErrorCode,
            String latestJobErrorDetail,
            UUID latestSuccessId,
            String latestSuccessMode,
            String latestSuccessSourceUri,
            String latestSuccessSourceVersion,
            String latestSuccessSourceSha256,
            Instant latestSuccessSourcePublishedAt,
            Instant latestSuccessObservedAt,
            Instant latestSuccessCompletedAt,
            Long latestSuccessRecordCount
    ) {
    }

    List<ProviderStatus> readStatus() throws IOException;
}
