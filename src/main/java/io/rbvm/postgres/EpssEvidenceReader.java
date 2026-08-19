package io.rbvm.postgres;

import java.io.IOException;
import java.util.Map;

/** Runtime read boundary for current tenant-scoped EPSS probability evidence. */
@FunctionalInterface
public interface EpssEvidenceReader {
    Map<String, Object> currentEvidence(int limit, String cvePrefix) throws IOException;
}
