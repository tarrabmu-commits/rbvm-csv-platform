package io.rbvm.postgres;

import java.util.Objects;

/** Idempotent outcome of installing one immutable RBVM methodology policy revision. */
public record DecisionMethodologyPolicyInstallResult(
        Status status,
        int requestedRevision,
        String requestedPolicySha256,
        Integer existingRevision,
        String existingPolicySha256
) {
    public DecisionMethodologyPolicyInstallResult {
        status = Objects.requireNonNull(status, "status");
        if (requestedRevision < 1) {
            throw new IllegalArgumentException("requestedRevision must be positive");
        }
        requireSha(requestedPolicySha256, "requestedPolicySha256");
        if (existingRevision != null && existingRevision < 1) {
            throw new IllegalArgumentException("existingRevision must be positive when present");
        }
        if (existingPolicySha256 != null) {
            requireSha(existingPolicySha256, "existingPolicySha256");
        }
        if (existingRevision == null || existingPolicySha256 == null) {
            throw new IllegalArgumentException(
                    "Methodology install outcomes must identify the persisted/conflicting revision and SHA");
        }
        if (status == Status.INSERTED || status == Status.REPLAYED) {
            if (existingRevision != requestedRevision
                    || !existingPolicySha256.equals(requestedPolicySha256)) {
                throw new IllegalArgumentException(
                        "Successful methodology install identity must match the request");
            }
        }
        if (status == Status.REVISION_CONFLICT && existingRevision != requestedRevision) {
            throw new IllegalArgumentException(
                    "Revision conflict must identify the same requested revision");
        }
    }

    public boolean installedOrReplayed() {
        return status == Status.INSERTED || status == Status.REPLAYED;
    }

    public enum Status {
        INSERTED,
        REPLAYED,
        REVISION_CONFLICT
    }

    private static void requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }
}
