package io.rbvm.csv;

import io.rbvm.decision.RbvmDerivedRiskCanonicalResult;
import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.postgres.DefaultDerivedRiskResultMaterializer;
import io.rbvm.postgres.DerivedRiskResultInstallResult;
import io.rbvm.postgres.DerivedRiskResultMaterializationResult;
import io.rbvm.postgres.DerivedRiskResultMaterializer;
import io.rbvm.postgres.DerivedRiskResultReplayVerifier;
import io.rbvm.postgres.DerivedRiskResultStore;
import io.rbvm.postgres.StoredDerivedRiskResult;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Exact-identity API contract for replay-verified derived risk methodologies and results. */
public final class DerivedRiskResultApi {
    public static final String CONTRACT_ID = "RBVM_DERIVED_RISK_RESULT_API_V1";
    public static final String CATALOG_CONTRACT_ID =
            "RBVM_DERIVED_RISK_METHODOLOGY_CATALOG_API_V1";
    public static final String MATERIALIZATION_CONTRACT_ID =
            "RBVM_DERIVED_RISK_RESULT_MATERIALIZATION_API_V1";

    private final DerivedRiskResultStore results;
    private final DerivedRiskResultReplayVerifier replayVerifier;
    private final DerivedRiskResultMaterializer materializer;

    public DerivedRiskResultApi(
            DerivedRiskResultStore results,
            DerivedRiskResultReplayVerifier replayVerifier,
            DerivedRiskResultMaterializer materializer
    ) {
        this.results = Objects.requireNonNull(results, "results");
        this.replayVerifier = Objects.requireNonNull(replayVerifier, "replayVerifier");
        this.materializer = Objects.requireNonNull(materializer, "materializer");
    }

    /** Deterministic discovery only. Catalog ordering has no default or precedence semantics. */
    public Response listMethodologies() {
        List<Map<String, Object>> methodologies = RbvmDerivedRiskMethodologyCatalog.definitions()
                .stream()
                .map(DerivedRiskResultApi::definitionView)
                .toList();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractId", CATALOG_CONTRACT_ID);
        body.put("selectionSemantics", "EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT");
        body.put("methodologies", methodologies);
        return new Response(200, Map.of(), body);
    }

    /** Exact immutable lookup by canonical derived result SHA-256 identity. */
    public Response getByResultSha256(String resultSha256) throws IOException {
        String sha = requireSha(resultSha256, "resultSha256");
        StoredDerivedRiskResult stored = results.findByResultSha256(sha).orElseThrow(() ->
                new ApiProblem(
                        404,
                        "DERIVED_RISK_RESULT_NOT_FOUND",
                        "No persisted derived risk result has the requested canonical identity"
                ));
        return response(stored);
    }

    /** Exact immutable lookup by Decision Input snapshot plus exact methodology ID/SHA identity. */
    public Response getByInputSnapshotAndMethodology(
            String inputSnapshotSha256,
            String methodologyId,
            String methodologySha256
    ) throws IOException {
        String snapshotSha = requireSha(inputSnapshotSha256, "inputSnapshotSha256");
        RbvmDerivedRiskMethodology.Definition definition = requireMethodologyIdentity(
                methodologyId,
                methodologySha256
        );
        StoredDerivedRiskResult stored = results.findBySnapshotAndMethodology(
                        snapshotSha,
                        definition.methodologyId(),
                        definition.methodologySha256()
                )
                .orElseThrow(() -> new ApiProblem(
                        404,
                        "DERIVED_RISK_RESULT_NOT_FOUND",
                        "No persisted derived risk result matches the exact input and methodology identity"
                ));
        return response(stored);
    }

    /** Explicit materialization from one exact persisted Decision Input V3 and exact methodology. */
    public Response materialize(
            String inputSnapshotSha256,
            String methodologyId,
            String methodologySha256
    ) throws IOException {
        String snapshotSha = requireSha(inputSnapshotSha256, "inputSnapshotSha256");
        RbvmDerivedRiskMethodology.Definition requested = requireMethodologyIdentity(
                methodologyId,
                methodologySha256
        );
        DerivedRiskResultMaterializationResult materialized;
        try {
            materialized = materializer.materialize(
                    snapshotSha,
                    requested.methodologyId(),
                    requested.methodologySha256()
            );
        } catch (DefaultDerivedRiskResultMaterializer.SnapshotNotFoundException exception) {
            throw new ApiProblem(
                    404,
                    "DECISION_INPUT_SNAPSHOT_NOT_FOUND",
                    "No persisted Decision Input snapshot has the requested exact identity"
            );
        } catch (DefaultDerivedRiskResultMaterializer.UnsupportedSnapshotContractException exception) {
            throw new ApiProblem(
                    422,
                    "DERIVED_RISK_MATERIALIZATION_REQUIRES_DECISION_INPUT_V3",
                    "Derived risk materialization accepts only a persisted Decision Input Snapshot V3"
            );
        } catch (DefaultDerivedRiskResultMaterializer.MethodologyNotFoundException
                 | DefaultDerivedRiskResultMaterializer.MethodologyIdentityMismatchException exception) {
            throw new ApiProblem(
                    404,
                    "DERIVED_RISK_METHODOLOGY_NOT_FOUND",
                    "No implemented derived risk methodology matches the requested exact identity"
            );
        } catch (DefaultDerivedRiskResultMaterializer.ResultConflictException exception) {
            throw new ApiProblem(
                    409,
                    "DERIVED_RISK_RESULT_CONFLICT",
                    "A conflicting derived risk result is already persisted for this exact input and methodology"
            );
        }

        DerivedRiskResultInstallResult.Status installStatus = materialized.installResult().status();
        StoredDerivedRiskResult stored = materialized.storedResult();
        int status = installStatus == DerivedRiskResultInstallResult.Status.INSERTED ? 201 : 200;
        String resultSha = stored.resultSha256();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractId", MATERIALIZATION_CONTRACT_ID);
        body.put("materializationStatus", installStatus.name());
        body.put("inputSnapshotSha256", stored.inputSnapshotSha256());
        body.put("resultId", stored.id().toString());
        body.put("methodology", storedMethodologyView(stored));
        body.put("resultState", stored.resultState().name());
        body.put("reasonCode", stored.reasonCode());
        body.put("numericScore", decimal(stored.numericScore()));
        body.put("numericScale", stored.numericScale());
        body.put("rating", stored.rating());
        body.put("resultSha256", resultSha);
        body.put("replayVerified", true);
        body.put("persistedAt", stored.persistedAt().toString());

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("ETag", strongEtag(resultSha));
        headers.put("Location", "/api/v1/derived-risk-results/" + resultSha);
        return new Response(status, headers, body);
    }

    private Response response(StoredDerivedRiskResult stored) throws IOException {
        RbvmDerivedRiskCanonicalResult replayed = replayVerifier.replay(stored);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractId", CONTRACT_ID);
        body.put("result", resultView(stored));
        body.put("canonicalResult", canonicalView(replayed));
        return new Response(
                200,
                Map.of("ETag", strongEtag(stored.resultSha256())),
                body
        );
    }

    private static Map<String, Object> resultView(StoredDerivedRiskResult stored) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("resultId", stored.id().toString());
        output.put("inputSnapshotSha256", stored.inputSnapshotSha256());
        output.put("findingId", stored.findingId().toString());
        output.put("methodology", storedMethodologyView(stored));
        output.put("resultState", stored.resultState().name());
        output.put("reasonCode", stored.reasonCode());
        output.put("numericScore", decimal(stored.numericScore()));
        output.put("numericScale", stored.numericScale());
        output.put("rating", stored.rating());
        output.put("persistedAt", stored.persistedAt().toString());
        return output;
    }

    private static Map<String, Object> canonicalView(RbvmDerivedRiskCanonicalResult canonical) {
        RbvmDerivedRiskMethodology.Evaluation evaluation = canonical.evaluation();
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("payloadFormat", RbvmDerivedRiskCanonicalResult.PAYLOAD_FORMAT);
        output.put("sha256", canonical.canonicalSha256());
        output.put(
                "canonicalPayloadBase64",
                Base64.getEncoder().encodeToString(canonical.canonicalPayload())
        );
        output.put("replayVerified", true);
        output.put(
                "measures",
                evaluation.measures().stream().map(DerivedRiskResultApi::measureView).toList()
        );
        return output;
    }

    private static Map<String, Object> measureView(RbvmDerivedRiskMethodology.Measure measure) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("measureId", measure.measureId());
        output.put("role", measure.role());
        output.put("value", measure.value().toPlainString());
        output.put("scale", measure.scale());
        return output;
    }

    private static Map<String, Object> storedMethodologyView(StoredDerivedRiskResult stored) {
        RbvmDerivedRiskMethodology.Definition definition = requireMethodologyIdentity(
                stored.methodologyId(),
                stored.methodologySha256()
        );
        if (definition.version() != stored.methodologyVersion()) {
            throw new IllegalStateException(
                    "Persisted derived risk methodology version does not match implementation"
            );
        }
        return definitionView(definition);
    }

    private static Map<String, Object> definitionView(RbvmDerivedRiskMethodology.Definition definition) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("methodologyId", definition.methodologyId());
        output.put("version", definition.version());
        output.put("classification", definition.classification().name());
        output.put("provider", definition.provider());
        output.put("sourceModel", definition.sourceModel());
        output.put("sourceEquation", definition.sourceEquation());
        output.put("sourceUrl", definition.sourceUrl());
        output.put("methodologySha256", definition.methodologySha256());
        output.put("outputName", definition.outputName());
        return output;
    }

    private static RbvmDerivedRiskMethodology.Definition requireMethodologyIdentity(
            String methodologyId,
            String methodologySha256
    ) {
        String id = requireText(methodologyId, "methodologyId");
        String sha = requireSha(methodologySha256, "methodologySha256");
        RbvmDerivedRiskMethodology methodology = RbvmDerivedRiskMethodologyCatalog.find(id)
                .orElseThrow(() -> new ApiProblem(
                        404,
                        "DERIVED_RISK_METHODOLOGY_NOT_FOUND",
                        "No implemented derived risk methodology matches the requested exact identity"
                ));
        RbvmDerivedRiskMethodology.Definition definition = methodology.definition();
        if (!definition.methodologyId().equals(id)
                || !definition.methodologySha256().equals(sha)) {
            throw new ApiProblem(
                    404,
                    "DERIVED_RISK_METHODOLOGY_NOT_FOUND",
                    "No implemented derived risk methodology matches the requested exact identity"
            );
        }
        return definition;
    }

    private static String decimal(BigDecimal value) {
        return value == null ? null : value.toPlainString();
    }

    static String strongEtag(String resultSha256) {
        return "\"derived-risk-result-" + requireSha(resultSha256, "resultSha256") + "\"";
    }

    static String requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new ApiProblem(
                    400,
                    "INVALID_DERIVED_RISK_IDENTITY",
                    field + " must be a lowercase SHA-256"
            );
        }
        return value;
    }

    static String requireText(String value, String field) {
        if (value == null || value.isBlank() || value.indexOf('\u0000') >= 0) {
            throw new ApiProblem(
                    400,
                    "INVALID_DERIVED_RISK_IDENTITY",
                    field + " must be non-empty text"
            );
        }
        return value.trim();
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

        public int status() { return status; }
        public String code() { return code; }
    }
}
