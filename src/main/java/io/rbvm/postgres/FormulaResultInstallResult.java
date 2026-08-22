package io.rbvm.postgres;

import java.util.Objects;

/** Idempotent outcome of installing one immutable Formula result/explanation identity. */
public record FormulaResultInstallResult(
        Status status,
        String requestedExplanationSha256,
        String existingExplanationSha256
) {
    public FormulaResultInstallResult {
        status = Objects.requireNonNull(status, "status");
        requireSha(requestedExplanationSha256, "requestedExplanationSha256");
        requireSha(existingExplanationSha256, "existingExplanationSha256");
        if ((status == Status.INSERTED || status == Status.REPLAYED)
                && !requestedExplanationSha256.equals(existingExplanationSha256)) {
            throw new IllegalArgumentException(
                    "Successful Formula-result install identity must match the request"
            );
        }
        if (status == Status.RESULT_CONFLICT
                && requestedExplanationSha256.equals(existingExplanationSha256)) {
            throw new IllegalArgumentException(
                    "Formula-result conflict requires different canonical explanation content"
            );
        }
    }

    public boolean installedOrReplayed() {
        return status == Status.INSERTED || status == Status.REPLAYED;
    }

    public enum Status {
        INSERTED,
        REPLAYED,
        RESULT_CONFLICT
    }

    private static void requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }
}
