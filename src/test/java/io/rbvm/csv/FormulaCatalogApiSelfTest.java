package io.rbvm.csv;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmFormulaV1;

import java.util.List;
import java.util.Map;

public final class FormulaCatalogApiSelfTest {
    private FormulaCatalogApiSelfTest() {
    }

    public static void main(String[] args) {
        exposesExactFormulaIdentityWithoutSelectionPreference();
        System.out.println("FormulaCatalogApiSelfTest: PASS");
    }

    private static void exposesExactFormulaIdentityWithoutSelectionPreference() {
        FormulaCatalogApi.Response response = new FormulaCatalogApi().listFormulas();
        assert response.status() == 200;
        assert response.headers().isEmpty();
        assert response.body().get("contractId").equals(FormulaCatalogApi.CONTRACT_ID);
        assert response.body().get("selectionSemantics")
                .equals(FormulaCatalogApi.SELECTION_SEMANTICS);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> formulas =
                (List<Map<String, Object>>) response.body().get("formulas");
        assert formulas.size() == 1 : formulas;
        Map<String, Object> formula = formulas.get(0);
        assert formula.get("formulaId").equals(RbvmFormulaV1.FORMULA_ID);
        assert formula.get("formulaVersion").equals(RbvmFormulaV1.FORMULA_VERSION);
        assert formula.get("formulaSha256").equals(RbvmFormulaV1.FORMULA_SHA256);
        assert formula.get("classification").equals("RBVM_POLICY");
        assert formula.get("inputContractId").equals(RbvmDecisionInputSnapshot.V3_ID);
        assert formula.get("outputName").equals(RbvmFormulaV1.OUTPUT_NAME);
        assert formula.get("numericMinimum").equals("0.00");
        assert formula.get("numericMaximum").equals("100.00");
        assert formula.get("resultStates").equals(List.of(
                "COMPUTED", "NOT_APPLICABLE", "NON_COMPUTABLE"
        ));
        assert formula.get("outputSemantics").equals(
                "DIMENSIONLESS_RELATIVE_RISK_INDEX_NOT_PRIORITY_SLA_TREATMENT_OR_PROBABILITY"
        );

        assert !response.body().containsKey("defaultFormula");
        assert !response.body().containsKey("preferredFormula");
        assert !response.body().containsKey("latestFormula");
    }
}
