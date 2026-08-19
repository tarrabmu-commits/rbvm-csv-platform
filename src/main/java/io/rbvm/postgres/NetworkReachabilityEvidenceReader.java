package io.rbvm.postgres;

import java.io.IOException;
import java.util.Map;

/** Runtime read boundary for current tenant-scoped network reachability evidence. */
@FunctionalInterface
public interface NetworkReachabilityEvidenceReader {
    Map<String, Object> currentEvidence(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String evidenceSource,
            String originScope,
            String reachabilityStatus
    ) throws IOException;
}
