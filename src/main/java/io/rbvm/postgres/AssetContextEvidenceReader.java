package io.rbvm.postgres;

import java.io.IOException;
import java.util.Map;

/** Runtime read boundary for current tenant-scoped organizational asset context evidence. */
@FunctionalInterface
public interface AssetContextEvidenceReader {
    Map<String, Object> currentEvidence(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String contextSource
    ) throws IOException;
}
