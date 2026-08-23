package io.rbvm.postgres;

import java.util.Objects;

/** Outcome of installing one immutable exact execution binding. */
public record ActiveRiskMethodExecutionBindingInstallResult(
        Status status,
        String requestedBindingSha256,
        String observedBindingSha256
) {
    public ActiveRiskMethodExecutionBindingInstallResult {
        Objects.requireNonNull(status, "status");
        requireSha(requestedBindingSha256, "requestedBindingSha256");
        requireSha(observedBindingSha256, "observedBindingSha256");
    }

    public enum Status {
        INSERTED,
        REPLAYED,
        EXECUTION_CONFLICT
    }

    private static void requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }
}
