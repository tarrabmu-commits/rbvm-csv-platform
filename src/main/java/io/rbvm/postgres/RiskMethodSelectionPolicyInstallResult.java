package io.rbvm.postgres;

import java.util.Objects;

/** Idempotent outcome of installing one immutable primary risk-method selection policy revision. */
public record RiskMethodSelectionPolicyInstallResult(
        Status status,
        int requestedRevision,
        String requestedPolicySha256,
        int existingRevision,
        String existingPolicySha256
) {
    public RiskMethodSelectionPolicyInstallResult {
        status = Objects.requireNonNull(status, "status");
        if (requestedRevision < 1 || existingRevision < 1) {
            throw new IllegalArgumentException("policy revisions must be positive");
        }
        requireSha(requestedPolicySha256, "requestedPolicySha256");
        requireSha(existingPolicySha256, "existingPolicySha256");
        if (status == Status.INSERTED || status == Status.REPLAYED) {
            if (existingRevision != requestedRevision
                    || !existingPolicySha256.equals(requestedPolicySha256)) {
                throw new IllegalArgumentException(
                        "Successful risk method selection install identity must match the request");
            }
        }
        if (status == Status.REVISION_CONFLICT && existingRevision != requestedRevision) {
            throw new IllegalArgumentException(
                    "Revision conflict must identify the requested revision");
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
