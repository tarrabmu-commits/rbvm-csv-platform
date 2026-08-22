package io.rbvm.postgres;

import java.util.Objects;

/** Result of append/replay installing one canonical derived-risk result. */
public record DerivedRiskResultInstallResult(
        Status status,
        String requestedResultSha256,
        String persistedResultSha256
) {
    public enum Status {
        INSERTED,
        REPLAYED,
        RESULT_CONFLICT
    }

    public DerivedRiskResultInstallResult {
        status = Objects.requireNonNull(status, "status");
        requestedResultSha256 = requireSha(requestedResultSha256, "requestedResultSha256");
        persistedResultSha256 = requireSha(persistedResultSha256, "persistedResultSha256");
    }

    private static String requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
        return value;
    }
}
