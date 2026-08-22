package io.rbvm.csv;

import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmFormulaV1Explanation;
import io.rbvm.decision.RbvmFormulaV1Explanation.DimensionExplanation;
import io.rbvm.postgres.FormulaResultReplayVerifier;
import io.rbvm.postgres.FormulaResultStore;
import io.rbvm.postgres.StoredFormulaResult;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Read-only contract logic for immutable, replay-verified RBVM Formula results.
 *
 * <p>This API exposes only exact persisted Formula identities. It never chooses a "latest" result,
 * rebuilds a Decision Input, re-selects current evidence, derives Priority/Treatment/SLA, or treats
 * a terminal result as numeric risk.</p>
 */
public final class FormulaResultApi {
    public static final String CONTRACT_ID = "RBVM_FORMULA_RESULT_API_V1";

    private final FormulaResultStore results;
    private final FormulaResultReplayVerifier replayVerifier;

    public FormulaResultApi(
            FormulaResultStore results,
            FormulaResultReplayVerifier replayVerifier
    ) {
        this.results = Objects.requireNonNull(results, "results");
        this.replayVerifier = Objects.requireNonNull(replayVerifier, "replayVerifier");
    }

    /** Exact immutable lookup by canonical explanation SHA-256 identity. */
    public Response getByExplanationSha256(String explanationSha256) throws IOException {
        String sha = requireSha(explanationSha256, "explanationSha256");
        StoredFormulaResult stored = results.findByExplanationSha256(sha).orElseThrow(() ->
                new ApiProblem(
                        404,
                        "FORMULA_RESULT_NOT_FOUND",
                        "No persisted Formula result has the requested explanation identity"
                ));
        return response(stored);
    }

    /** Exact immutable lookup by Decision Input snapshot SHA and Formula SHA. */
    public Response getByInputSnapshotAndFormula(
            String inputSnapshotSha256,
            String formulaSha256
    ) throws IOException {
        String snapshotSha = requireSha(inputSnapshotSha256, "inputSnapshotSha256");
        String formulaSha = requireSha(formulaSha256, "formulaSha256");
        StoredFormulaResult stored = results
                .findBySnapshotAndFormula(snapshotSha, formulaSha)
                .orElseThrow(() -> new ApiProblem(
                        404,
                        "FORMULA_RESULT_NOT_FOUND",
                        "No persisted Formula result matches the requested input and Formula identity"
                ));
        return response(stored);
    }

    private Response response(StoredFormulaResult stored) throws IOException {
        RbvmFormulaV1Explanation explanation = replayVerifier.replay(stored);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractId", CONTRACT_ID);
        body.put("result", resultView(stored));
        body.put("explanation", explanationView(explanation));
        return new Response(
                200,
                Map.of("ETag", strongEtag(stored.explanationSha256())),
                body
        );
    }

    private static Map<String, Object> resultView(StoredFormulaResult stored) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("resultId", stored.id().toString());
        output.put("inputSnapshotSha256", stored.inputSnapshotSha256());
        output.put("findingId", stored.findingId().toString());
        output.put("evaluatedAt", stored.evaluatedAt().toString());
        output.put("methodologyRevision", stored.methodologyRevision());
        output.put("methodologyPolicySha256", stored.methodologyPolicySha256());
        output.put("formulaId", stored.formulaId());
        output.put("formulaVersion", stored.formulaVersion());
        output.put("formulaSha256", stored.formulaSha256());
        output.put("resultState", stored.resultState().name());
        output.put("reasonCodes", stored.reasonCodes());
        output.put("relativeRiskIndex", decimal(stored.relativeRiskIndex()));
        output.put("persistedAt", stored.persistedAt().toString());
        return output;
    }

    private static Map<String, Object> explanationView(RbvmFormulaV1Explanation explanation) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("payloadFormat", RbvmFormulaV1Explanation.PAYLOAD_FORMAT);
        output.put("sha256", explanation.canonicalSha256());
        output.put(
                "canonicalPayloadBase64",
                Base64.getEncoder().encodeToString(explanation.canonicalPayload())
        );
        output.put("replayVerified", true);
        output.put(
                "dimensions",
                explanation.dimensions().stream().map(FormulaResultApi::dimensionView).toList()
        );
        return output;
    }

    private static Map<String, Object> dimensionView(DimensionExplanation dimension) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("dimension", dimension.dimension().name());
        output.put("state", dimension.state().name());
        output.put("normalizedValue", dimension.normalizedValue());
        output.put("appliedFactorOrTransformId", dimension.appliedFactorOrTransformId());
        output.put("weightedContribution", decimal(dimension.weightedContribution()));
        output.put(
                "evidenceReferences",
                dimension.evidenceReferences().stream()
                        .map(FormulaResultApi::evidenceReferenceView)
                        .toList()
        );
        return output;
    }

    private static Map<String, Object> evidenceReferenceView(EvidenceReference reference) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("nativeEvidenceKind", reference.nativeEvidenceKind().name());
        output.put("evidenceId", reference.evidenceId().toString());
        output.put("evidenceSha256", reference.evidenceSha256());
        output.put("evidenceSource", reference.evidenceSource());
        output.put("observedAt", reference.observedAt().toString());
        output.put("binding", bindingView(reference.bindingReference()));
        return output;
    }

    private static Map<String, Object> bindingView(BindingReference binding) {
        if (binding == null) return null;
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("bindingKind", binding.bindingKind().name());
        output.put("bindingId", binding.bindingId().toString());
        output.put("bindingSha256", binding.bindingSha256());
        output.put("bindingSource", binding.bindingSource());
        output.put("recordedAt", binding.recordedAt().toString());
        return output;
    }

    private static String decimal(BigDecimal value) {
        return value == null ? null : value.toPlainString();
    }

    static String strongEtag(String explanationSha256) {
        return "\"formula-result-" + requireSha(explanationSha256, "explanationSha256") + "\"";
    }

    static String requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new ApiProblem(
                    400,
                    "INVALID_FORMULA_RESULT_IDENTITY",
                    field + " must be a lowercase SHA-256"
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
            if (status < 100 || status > 599) {
                throw new IllegalArgumentException("status must be an HTTP status code");
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
