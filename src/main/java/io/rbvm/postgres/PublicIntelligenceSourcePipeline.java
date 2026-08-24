package io.rbvm.postgres;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Set;

/** Acquisition/build boundary used by the server-side public-intelligence coordinator. */
public interface PublicIntelligenceSourcePipeline {
    record AcquiredSource(
            PostgresPublicIntelligenceStore.Provider provider,
            String nvdFeed,
            String sourceUri,
            String sourceVersion,
            String sourceSha256,
            Path acquisitionDirectory
    ) {
    }

    AcquiredSource acquire(
            PostgresPublicIntelligenceStore.Provider provider,
            String nvdFeed,
            Path workDirectory,
            Instant observedAt
    ) throws IOException, InterruptedException;

    Path buildBundle(
            AcquiredSource source,
            Set<String> previousCurrentCves,
            Path workDirectory
    ) throws IOException, InterruptedException;
}
