package io.rbvm.csv;

import io.rbvm.postgres.DefaultFormulaResultMaterializer;
import io.rbvm.postgres.FormulaResultInstallResult;
import io.rbvm.postgres.FormulaResultMaterializationResult;
import io.rbvm.postgres.FormulaResultMaterializer;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Application contract for explicit Formula V1 materialization from one exact persisted input. */
public final class FormulaResultMaterializationApi {
    public static final String CONTRACT_ID = "RBVM_FORMULA_RESULT_MATERIALIZATION_API_V1";

    private final FormulaResultMaterializer materializer;
    private final FormulaResultApi formulaResults;

    public FormulaResultMaterializationApi(
            FormulaResultMaterializer materializer,
            FormulaResultApi formulaResults
    ) {
        this.materializer = Objects.requireNonNull(materializer, "materializer");
        this.formulaResults = Objects.requireNonNull(formulaResults, "formulaResults");
    }

    public Response materialize(String inputSnapshotSha256) throws IOException {
        String snapshotSha = requireSha(inputSnapshotSha256);
        FormulaResultMaterializationResult materialized;
        try {
            materialized = materializer.materialize(snapshotSha);
        } catch (DefaultFormulaResultMaterializer.SnapshotNotFoundException exception) {
            throw new ApiProblem(
                    404,
                    "DECISION_INPUT_SNAPSHOT_NOT_FOUND",
                    "No persisted Decision Input snapshot has the requested exact identity"
            );
        } catch (DefaultFormulaResultMaterializer.UnsupportedSnapshotContractException exception) {
            throw new ApiProblem(
                    422,
                    "FORMULA_MATERIALIZATION_REQUIRES_DECISION_INPUT_V3",
                    "Formula V1 materialization accepts only a persisted Decision Input Snapshot V3"
            );
        } catch (DefaultFormulaResultMaterializer.ResultConflictException exception) {
            throw new ApiProblem(
                    409,
                    "FORMULA_RESULT_CONFLICT",
                    "A conflicting Formula result is already persisted for this exact Decision Input"
            );
        }

        FormulaResultApi.Response exactRead = formulaResults.getByExplanationSha256(
                materialized.explanation().canonicalSha256()
        );
        FormulaResultInstallResult.Status installStatus = materialized.installResult().status();
        int status = installStatus == FormulaResultInstallResult.Status.INSERTED ? 201 : 200;

        Map<String, String> headers = new LinkedHashMap<>(exactRead.headers());
        headers.put(
                "Location",
                "/api/v1/formula-results/" + materialized.explanation().canonicalSha256()
        );
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractId", CONTRACT_ID);
        body.put("materializationStatus", installStatus.name());
        body.put("inputSnapshotSha256", snapshotSha);
        body.put("formulaResult", exactRead.body());
        return new Response(status, headers, body);
    }

    static String requireSha(String value) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new ApiProblem(
                    400,
                    "INVALID_DECISION_INPUT_SNAPSHOT_IDENTITY",
                    "inputSnapshotSha256 must be a lowercase SHA-256"
            );
        }
        return value;
    }

    public record Response(
            int status,
            Map<String, String> headers,
            Map<String, Object> body
    ) {
        public Response {
            if (status != 200 && status != 201) {
                throw new IllegalArgumentException("materialization response must be 200 or 201");
            }
            headers = Map.copyOf(Objects.requireNonNull(headers, "headers"));
            body = Map.copyOf(Objects.requireNonNull(body, "body"));
        }
    }

    public static final class ApiProblem extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final int status;
        private final String code;

        public ApiProblem(int status, String code, String detail) {
            super(Objects.requireNonNull(detail, "detail"));
            if (status < 400 || status > 599) {
                throw new IllegalArgumentException("problem status must be 4xx or 5xx");
            }
            this.status = status;
            this.code = Objects.requireNonNull(code, "code");
        }

        public int status() {
            return status;
        }

        public String code() {
            return code;
        }
    }
}
