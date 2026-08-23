package io.rbvm.csv;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmFormulaV1;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Deterministic discovery contract for implemented immutable Formula identities. */
public final class FormulaCatalogApi {
    public static final String CONTRACT_ID = "RBVM_FORMULA_CATALOG_API_V1";
    public static final String SELECTION_SEMANTICS =
            "EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT";

    /**
     * Discovery only. List order is deterministic presentation order and carries no precedence.
     */
    public Response listFormulas() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractId", CONTRACT_ID);
        body.put("selectionSemantics", SELECTION_SEMANTICS);
        body.put("formulas", List.of(formulaV1Definition()));
        return new Response(200, Map.of(), body);
    }

    private static Map<String, Object> formulaV1Definition() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("formulaId", RbvmFormulaV1.FORMULA_ID);
        value.put("formulaVersion", RbvmFormulaV1.FORMULA_VERSION);
        value.put("formulaSha256", RbvmFormulaV1.FORMULA_SHA256);
        value.put("classification", "RBVM_POLICY");
        value.put("inputContractId", RbvmDecisionInputSnapshot.V3_ID);
        value.put("outputName", RbvmFormulaV1.OUTPUT_NAME);
        value.put("numericMinimum", "0.00");
        value.put("numericMaximum", "100.00");
        value.put(
                "resultStates",
                List.of(
                        RbvmFormulaV1.ResultState.COMPUTED.name(),
                        RbvmFormulaV1.ResultState.NOT_APPLICABLE.name(),
                        RbvmFormulaV1.ResultState.NON_COMPUTABLE.name()
                )
        );
        value.put(
                "outputSemantics",
                "DIMENSIONLESS_RELATIVE_RISK_INDEX_NOT_PRIORITY_SLA_TREATMENT_OR_PROBABILITY"
        );
        return Collections.unmodifiableMap(value);
    }

    public record Response(
            int status,
            Map<String, String> headers,
            Map<String, Object> body
    ) {
        public Response {
            if (status < 100 || status > 599) {
                throw new IllegalArgumentException("status must be an HTTP status code");
            }
            headers = Map.copyOf(Objects.requireNonNull(headers, "headers"));
            body = Collections.unmodifiableMap(
                    new LinkedHashMap<>(Objects.requireNonNull(body, "body"))
            );
        }
    }
}
