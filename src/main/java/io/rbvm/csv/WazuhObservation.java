package io.rbvm.csv;

import java.time.Instant;
import java.util.Objects;

/** Immutable, validated positive observation emitted by the WAZUH_CSV_V1 reader. */
public record WazuhObservation(
        long sourceRowNumber,
        String sourceProfileId,
        String observationFingerprint,
        String agentObservedName,
        String agentIdentityKey,
        String cveId,
        CsvSeverity severity,
        boolean sourceSeverityRecognized,
        String descriptionSnapshot,
        String affectedProductObservedName,
        String affectedProductIdentityKey,
        String referencesRaw,
        String osNameRaw,
        Instant detectedAt
) {
    public WazuhObservation {
        if (sourceRowNumber < 2) {
            throw new IllegalArgumentException("sourceRowNumber must include the header offset");
        }
        Objects.requireNonNull(sourceProfileId, "sourceProfileId");
        Objects.requireNonNull(observationFingerprint, "observationFingerprint");
        Objects.requireNonNull(agentObservedName, "agentObservedName");
        Objects.requireNonNull(agentIdentityKey, "agentIdentityKey");
        Objects.requireNonNull(cveId, "cveId");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(descriptionSnapshot, "descriptionSnapshot");
        Objects.requireNonNull(affectedProductObservedName, "affectedProductObservedName");
        Objects.requireNonNull(affectedProductIdentityKey, "affectedProductIdentityKey");
        Objects.requireNonNull(referencesRaw, "referencesRaw");
        Objects.requireNonNull(osNameRaw, "osNameRaw");
        Objects.requireNonNull(detectedAt, "detectedAt");
    }
}
