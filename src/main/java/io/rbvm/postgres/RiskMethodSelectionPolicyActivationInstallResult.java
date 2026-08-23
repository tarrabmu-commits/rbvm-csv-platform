package io.rbvm.postgres;

import java.util.Objects;

/** Idempotent outcome of appending one explicit risk-method policy activation event. */
public record RiskMethodSelectionPolicyActivationInstallResult(
        Status status,
        int requestedActivationRevision,
        String requestedEventSha256,
        int observedActivationRevision,
        String observedEventSha256
) {
    public RiskMethodSelectionPolicyActivationInstallResult {
        status = Objects.requireNonNull(status, "status");
        if (requestedActivationRevision < 1 || observedActivationRevision < 1) {
            throw new IllegalArgumentException("activation revisions must be positive");
        }
        requireSha(requestedEventSha256, "requestedEventSha256");
        requireSha(observedEventSha256, "observedEventSha256");
        if (status == Status.INSERTED || status == Status.REPLAYED) {
            if (requestedActivationRevision != observedActivationRevision
                    || !requestedEventSha256.equals(observedEventSha256)) {
                throw new IllegalArgumentException(
                        "successful activation install identity must match the request");
            }
        }
        if (status == Status.REVISION_CONFLICT
                && requestedActivationRevision != observedActivationRevision) {
            throw new IllegalArgumentException(
                    "activation revision conflict must identify the requested revision");
        }
        if (status == Status.STALE_ACTIVATION_REVISION
                && observedActivationRevision <= requestedActivationRevision) {
            throw new IllegalArgumentException(
                    "stale activation outcome must identify a greater current activation revision");
        }
    }

    public enum Status {
        INSERTED,
        REPLAYED,
        REVISION_CONFLICT,
        STALE_ACTIVATION_REVISION
    }

    private static void requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }
}
