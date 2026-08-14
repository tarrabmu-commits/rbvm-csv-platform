package io.rbvm.csv;

import java.time.Instant;
import java.util.Objects;

/** Immutable, validated source evidence emitted by a supported Wazuh CSV contract. */
public record WazuhObservation(
        long sourceRowNumber,
        String sourceProfileId,
        String contractId,
        String observationFingerprint,
        String agentObservedName,
        String agentSourceId,
        String agentIdentityKey,
        String cveId,
        CsvSeverity severity,
        boolean sourceSeverityRecognized,
        String descriptionSnapshot,
        String affectedProductObservedName,
        String packageVersion,
        String packageArchitecture,
        String affectedProductIdentityKey,
        String referencesRaw,
        String osNameRaw,
        FindingStatus findingStatus,
        Instant detectedAt,
        Instant resolvedAt,
        VulnerabilityIntelligenceEvidence intelligence
) {
    public WazuhObservation {
        if (sourceRowNumber < 2) {
            throw new IllegalArgumentException("sourceRowNumber must include the header offset");
        }
        Objects.requireNonNull(sourceProfileId, "sourceProfileId");
        Objects.requireNonNull(contractId, "contractId");
        Objects.requireNonNull(observationFingerprint, "observationFingerprint");
        Objects.requireNonNull(agentObservedName, "agentObservedName");
        Objects.requireNonNull(agentSourceId, "agentSourceId");
        Objects.requireNonNull(agentIdentityKey, "agentIdentityKey");
        Objects.requireNonNull(cveId, "cveId");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(descriptionSnapshot, "descriptionSnapshot");
        Objects.requireNonNull(affectedProductObservedName, "affectedProductObservedName");
        Objects.requireNonNull(packageVersion, "packageVersion");
        Objects.requireNonNull(packageArchitecture, "packageArchitecture");
        Objects.requireNonNull(affectedProductIdentityKey, "affectedProductIdentityKey");
        Objects.requireNonNull(referencesRaw, "referencesRaw");
        Objects.requireNonNull(osNameRaw, "osNameRaw");
        Objects.requireNonNull(findingStatus, "findingStatus");
        Objects.requireNonNull(detectedAt, "detectedAt");
        if (findingStatus == FindingStatus.ACTIVE && resolvedAt != null) {
            throw new IllegalArgumentException("ACTIVE evidence cannot have Resolved_At");
        }
        if (findingStatus == FindingStatus.RESOLVED
                && (resolvedAt == null || resolvedAt.isBefore(detectedAt))) {
            throw new IllegalArgumentException("RESOLVED evidence requires Resolved_At >= Detected_At");
        }
    }

    public Instant evidenceAt() {
        return resolvedAt == null ? detectedAt : resolvedAt;
    }
}
