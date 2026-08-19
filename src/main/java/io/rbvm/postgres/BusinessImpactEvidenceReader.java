package io.rbvm.postgres;

import java.io.IOException;
import java.util.Map;

/** Runtime read boundary for current tenant-scoped Business/Mission Impact evidence. */
@FunctionalInterface
public interface BusinessImpactEvidenceReader {
    Map<String, Object> currentEvidence(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String businessService,
            String impactSource,
            String impactDimension,
            String impactLevel
    ) throws IOException;
}
