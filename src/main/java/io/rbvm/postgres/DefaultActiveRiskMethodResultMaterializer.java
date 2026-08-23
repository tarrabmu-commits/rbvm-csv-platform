package io.rbvm.postgres;

import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding.ResultFamily;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;

import java.io.IOException;
import java.util.Objects;

/** Dispatches one exact selected risk method to its existing native result materializer. */
public final class DefaultActiveRiskMethodResultMaterializer
        implements ActiveRiskMethodResultMaterializer {
    private final FormulaResultMaterializer formulaResults;
    private final DerivedRiskResultMaterializer derivedResults;

    public DefaultActiveRiskMethodResultMaterializer(
            FormulaResultMaterializer formulaResults,
            DerivedRiskResultMaterializer derivedResults
    ) {
        this.formulaResults = Objects.requireNonNull(formulaResults, "formulaResults");
        this.derivedResults = Objects.requireNonNull(derivedResults, "derivedResults");
    }

    @Override
    public ActiveRiskMethodNativeResult materialize(
            RbvmRiskMethodSelectionPolicy policy,
            String inputSnapshotSha256
    ) throws IOException {
        Objects.requireNonNull(policy, "policy").requireCatalogBound();
        requireSha(inputSnapshotSha256, "inputSnapshotSha256");

        return switch (policy.methodFamily()) {
            case RBVM_FORMULA -> materializeFormula(policy, inputSnapshotSha256);
            case STANDARD_DERIVED -> materializeDerived(policy, inputSnapshotSha256);
        };
    }

    private ActiveRiskMethodNativeResult materializeFormula(
            RbvmRiskMethodSelectionPolicy policy,
            String inputSnapshotSha256
    ) throws IOException {
        FormulaResultMaterializationResult materialized =
                formulaResults.materialize(inputSnapshotSha256);
        StoredFormulaResult stored = materialized.storedResult();
        if (!stored.inputSnapshotSha256().equals(inputSnapshotSha256)
                || !stored.formulaId().equals(policy.methodId())
                || stored.formulaVersion() != policy.methodVersion()
                || !stored.formulaSha256().equals(policy.methodSha256())) {
            throw new ResultIdentityMismatchException(
                    "Formula materializer returned an identity different from the selected exact method"
            );
        }
        return new ActiveRiskMethodNativeResult(
                stored.inputSnapshotSha256(),
                policy.methodFamily(),
                stored.formulaId(),
                stored.formulaVersion(),
                stored.formulaSha256(),
                ResultFamily.RBVM_FORMULA_RESULT,
                stored.explanationSha256()
        );
    }

    private ActiveRiskMethodNativeResult materializeDerived(
            RbvmRiskMethodSelectionPolicy policy,
            String inputSnapshotSha256
    ) throws IOException {
        DerivedRiskResultMaterializationResult materialized = derivedResults.materialize(
                inputSnapshotSha256,
                policy.methodId(),
                policy.methodSha256()
        );
        StoredDerivedRiskResult stored = materialized.storedResult();
        if (!stored.inputSnapshotSha256().equals(inputSnapshotSha256)
                || !stored.methodologyId().equals(policy.methodId())
                || stored.methodologyVersion() != policy.methodVersion()
                || !stored.methodologySha256().equals(policy.methodSha256())) {
            throw new ResultIdentityMismatchException(
                    "Derived materializer returned an identity different from the selected exact method"
            );
        }
        return new ActiveRiskMethodNativeResult(
                stored.inputSnapshotSha256(),
                policy.methodFamily(),
                stored.methodologyId(),
                stored.methodologyVersion(),
                stored.methodologySha256(),
                ResultFamily.DERIVED_RISK_RESULT,
                stored.resultSha256()
        );
    }

    private static void requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }

    public static final class ResultIdentityMismatchException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public ResultIdentityMismatchException(String message) {
            super(message);
        }
    }
}
