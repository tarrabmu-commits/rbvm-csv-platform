package io.rbvm.postgres;

import java.io.IOException;
import java.util.Map;

/** Runtime read boundary for current tenant-scoped CVSS v3.1 Base evidence. */
@FunctionalInterface
public interface CvssV31EvidenceReader {
    Map<String, Object> currentEvidence(int limit, String cvePrefix) throws IOException;
}
