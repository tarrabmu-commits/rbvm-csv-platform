package io.rbvm.csv;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Finding-scoped evidence describing whether a detected vulnerability applies to the actual
 * component/deployment.
 *
 * <p>Scanner detection does not establish applicability. A finding therefore starts unassessed as
 * UNKNOWN. An explicit assessment may conclude APPLICABLE, NOT_APPLICABLE, or UNKNOWN, but every
 * assessed result must carry a reason, source, and evaluation timestamp.</p>
 */
public final class ApplicabilityEvidence {
    public enum Status {
        APPLICABLE,
        NOT_APPLICABLE,
        UNKNOWN
    }

    private final CanonicalFindingIdentity findingIdentity;
    private final Status status;
    private final boolean assessed;
    private final String reason;
    private final String evidenceSource;
    private final Instant evaluatedAt;

    private ApplicabilityEvidence(
            CanonicalFindingIdentity findingIdentity,
            Status status,
            boolean assessed,
            String reason,
            String evidenceSource,
            Instant evaluatedAt
    ) {
        this.findingIdentity = Objects.requireNonNull(findingIdentity, "findingIdentity");
        this.status = Objects.requireNonNull(status, "status");
        this.assessed = assessed;

        if (!assessed) {
            if (status != Status.UNKNOWN) {
                throw new IllegalArgumentException("Unassessed applicability must be UNKNOWN");
            }
            if (reason != null || evidenceSource != null || evaluatedAt != null) {
                throw new IllegalArgumentException(
                        "Unassessed applicability cannot contain assessment provenance");
            }
            this.reason = null;
            this.evidenceSource = null;
            this.evaluatedAt = null;
            return;
        }

        this.reason = requireText(reason, "reason");
        this.evidenceSource = requireText(evidenceSource, "evidenceSource");
        this.evaluatedAt = Objects.requireNonNull(evaluatedAt, "evaluatedAt");
    }

    public static ApplicabilityEvidence unassessed(CanonicalFindingIdentity findingIdentity) {
        return new ApplicabilityEvidence(
                findingIdentity,
                Status.UNKNOWN,
                false,
                null,
                null,
                null
        );
    }

    public static ApplicabilityEvidence assessed(
            CanonicalFindingIdentity findingIdentity,
            Status status,
            String reason,
            String evidenceSource,
            Instant evaluatedAt
    ) {
        return new ApplicabilityEvidence(
                findingIdentity,
                status,
                true,
                reason,
                evidenceSource,
                evaluatedAt
        );
    }

    public CanonicalFindingIdentity findingIdentity() {
        return findingIdentity;
    }

    public Status status() {
        return status;
    }

    public boolean assessed() {
        return assessed;
    }

    public String reason() {
        return reason;
    }

    public String evidenceSource() {
        return evidenceSource;
    }

    public Instant evaluatedAt() {
        return evaluatedAt;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("findingIdentity", findingIdentity.toMap());
        output.put("status", status.name());
        output.put("assessed", assessed);
        output.put("reason", reason);
        output.put("evidenceSource", evidenceSource);
        output.put("evaluatedAt", evaluatedAt == null ? null : evaluatedAt.toString());
        return output;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required for assessed applicability");
        }
        return value.trim();
    }
}
