package io.rbvm.csv;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * One explicit applicability assessment supplied by the dedicated applicability CSV contract.
 *
 * <p>The CSV references a platform-generated Finding_ID instead of repeating Wazuh identity fields.
 * This keeps WAZUH_CSV_V1 unchanged and prevents a secondary assessment file from inventing missing
 * Wazuh evidence.</p>
 */
public record ApplicabilityCsvAssessment(
        long sourceRowNumber,
        UUID findingId,
        ApplicabilityEvidence.Status status,
        String reason,
        String evidenceSource,
        Instant evaluatedAt
) {
    public ApplicabilityCsvAssessment {
        if (sourceRowNumber < 2) {
            throw new IllegalArgumentException("sourceRowNumber must be at least 2");
        }
        Objects.requireNonNull(findingId, "findingId");
        Objects.requireNonNull(status, "status");
        reason = requireText(reason, "reason");
        evidenceSource = requireText(evidenceSource, "evidenceSource");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
    }

    public ApplicabilityEvidence toEvidence(CanonicalFindingIdentity findingIdentity) {
        return ApplicabilityEvidence.assessed(
                Objects.requireNonNull(findingIdentity, "findingIdentity"),
                status,
                reason,
                evidenceSource,
                evaluatedAt
        );
    }

    public String assessmentKey() {
        return findingId + "\u001F" + evaluatedAt;
    }

    public String normalizedContentKey() {
        return status.name() + "\u001F" + reason + "\u001F" + evidenceSource;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }
}
