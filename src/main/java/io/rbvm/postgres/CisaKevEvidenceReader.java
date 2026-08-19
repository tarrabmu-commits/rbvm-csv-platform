package io.rbvm.postgres;

import java.io.IOException;
import java.util.Map;

/** Runtime read boundary for current tenant-scoped CISA KEV evidence. */
@FunctionalInterface
public interface CisaKevEvidenceReader {
    Map<String, Object> currentEvidence(int limit, String cvePrefix) throws IOException;
}
