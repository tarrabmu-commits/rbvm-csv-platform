package io.rbvm.postgres;

import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding.ResultFamily;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy.MethodFamily;

import java.util.Objects;

/** Exact native result identity returned by the selected executable risk method. */
public record ActiveRiskMethodNativeResult(
        String inputSnapshotSha256,
        MethodFamily methodFamily,
        String methodId,
        int methodVersion,
        String methodSha256,
        ResultFamily resultFamily,
        String resultSha256
) {
    public ActiveRiskMethodNativeResult {
        requireSha(inputSnapshotSha256, "inputSnapshotSha256");
        Objects.requireNonNull(methodFamily, "methodFamily");
        requireText(methodId, "methodId");
        if (methodVersion < 1) {
            throw new IllegalArgumentException("methodVersion must be positive");
        }
        requireSha(methodSha256, "methodSha256");
        Objects.requireNonNull(resultFamily, "resultFamily");
        requireSha(resultSha256, "resultSha256");
        if (methodFamily == MethodFamily.RBVM_FORMULA
                && resultFamily != ResultFamily.RBVM_FORMULA_RESULT) {
            throw new IllegalArgumentException("RBVM_FORMULA must emit RBVM_FORMULA_RESULT");
        }
        if (methodFamily == MethodFamily.STANDARD_DERIVED
                && resultFamily != ResultFamily.DERIVED_RISK_RESULT) {
            throw new IllegalArgumentException("STANDARD_DERIVED must emit DERIVED_RISK_RESULT");
        }
    }

    private static void requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank() || !value.equals(value.trim())
                || value.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " must be non-empty canonical text");
        }
    }
}
