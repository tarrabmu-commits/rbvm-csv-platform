package io.rbvm.postgres;

import java.util.Objects;

/** Idempotent outcome of installing one immutable Finding-scoped decision input snapshot. */
public record DecisionInputSnapshotInstallResult(
        Status status,
        String requestedSnapshotSha256,
        String existingSnapshotSha256
) {
    public DecisionInputSnapshotInstallResult {
        status = Objects.requireNonNull(status, "status");
        requireSha(requestedSnapshotSha256, "requestedSnapshotSha256");
        requireSha(existingSnapshotSha256, "existingSnapshotSha256");
        if ((status == Status.INSERTED || status == Status.REPLAYED)
                && !requestedSnapshotSha256.equals(existingSnapshotSha256)) {
            throw new IllegalArgumentException(
                    "Successful snapshot install identity must match the request");
        }
        if (status == Status.EVALUATION_CONFLICT
                && requestedSnapshotSha256.equals(existingSnapshotSha256)) {
            throw new IllegalArgumentException(
                    "Evaluation conflict requires different canonical snapshot content");
        }
    }

    public boolean installedOrReplayed() {
        return status == Status.INSERTED || status == Status.REPLAYED;
    }

    public enum Status {
        INSERTED,
        REPLAYED,
        EVALUATION_CONFLICT
    }

    private static void requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }
}
