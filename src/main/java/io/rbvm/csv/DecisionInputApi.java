package io.rbvm.csv;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy;
import io.rbvm.postgres.DecisionInputRuntimeAccess;
import io.rbvm.postgres.DecisionInputSnapshotInstallResult;
import io.rbvm.postgres.DecisionInputSnapshotMaterializationResult;

import java.io.IOException;
import java.io.InputStream;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Exact-identity HTTP contract logic for immutable Decision Input snapshots and methodologies.
 *
 * <p>Nothing in this API chooses a latest/current/preferred methodology or snapshot. Mutation
 * requires an explicit Finding, methodology revision/SHA, and evaluation instant. Read paths are
 * exact identity or history/catalog views only.</p>
 */
public final class DecisionInputApi {
    public static final String CONTRACT_ID = "RBVM_DECISION_INPUT_API_V1";
    public static final String MATERIALIZATION_CONTRACT_ID =
            "RBVM_DECISION_INPUT_MATERIALIZATION_API_V1";
    public static final String METHODOLOGY_CATALOG_CONTRACT_ID =
            "RBVM_DECISION_METHODOLOGY_CATALOG_API_V1";

    private static final Set<String> MATERIALIZATION_FIELDS = Set.of(
            "findingId",
            "methodologyRevision",
            "methodologyPolicySha256",
            "evaluatedAt"
    );

    private final DecisionInputRuntimeAccess runtime;

    public DecisionInputApi(DecisionInputRuntimeAccess runtime) {
        this.runtime = Objects.requireNonNull(runtime, "runtime");
    }

    public Response getSnapshot(String snapshotSha256) throws IOException {
        String sha = requireSha(snapshotSha256, "snapshotSha256");
        RbvmDecisionInputSnapshot snapshot = runtime.findSnapshot(sha).orElseThrow(() ->
                new ApiProblem(
                        404,
                        "DECISION_INPUT_SNAPSHOT_NOT_FOUND",
                        "No persisted Decision Input snapshot has the requested exact identity"
                ));
        return new Response(
                200,
                Map.of("ETag", strongEtag(snapshot.snapshotSha256())),
                Map.of("contractId", CONTRACT_ID, "snapshot", snapshotView(snapshot))
        );
    }

    public Response history(
            UUID findingId,
            int limit,
            Instant beforeEvaluatedAt,
            String beforeSnapshotSha256
    ) throws IOException {
        DecisionInputRuntimeAccess.SnapshotHistoryPage page;
        try {
            page = runtime.history(
                    Objects.requireNonNull(findingId, "findingId"),
                    limit,
                    beforeEvaluatedAt,
                    beforeSnapshotSha256
            );
        } catch (IllegalArgumentException exception) {
            throw new ApiProblem(400, "INVALID_DECISION_INPUT_HISTORY_QUERY", exception.getMessage());
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractId", CONTRACT_ID);
        body.put("findingId", findingId.toString());
        body.put(
                "snapshots",
                page.snapshots().stream().map(DecisionInputApi::snapshotSummaryView).toList()
        );
        body.put(
                "nextBeforeEvaluatedAt",
                page.nextBeforeEvaluatedAt() == null
                        ? null
                        : page.nextBeforeEvaluatedAt().toString()
        );
        body.put("nextBeforeSnapshotSha256", page.nextBeforeSnapshotSha256());
        return new Response(200, Map.of(), body);
    }

    public Response methodologies(int limit, Integer afterRevision) throws IOException {
        DecisionInputRuntimeAccess.MethodologyPage page;
        try {
            page = runtime.methodologies(limit, afterRevision);
        } catch (IllegalArgumentException exception) {
            throw new ApiProblem(400, "INVALID_DECISION_METHODOLOGY_QUERY", exception.getMessage());
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractId", METHODOLOGY_CATALOG_CONTRACT_ID);
        body.put(
                "methodologies",
                page.methodologies().stream().map(DecisionInputApi::methodologyView).toList()
        );
        body.put("nextAfterRevision", page.nextAfterRevision());
        body.put(
                "orderingSemantics",
                "REVISION_ASCENDING_FOR_PAGINATION_ONLY_NO_PRECEDENCE_OR_PREFERENCE"
        );
        return new Response(200, Map.of(), body);
    }

    public Response getMethodology(int revision) throws IOException {
        if (revision < 1) {
            throw new ApiProblem(
                    400,
                    "INVALID_DECISION_METHODOLOGY_IDENTITY",
                    "revision must be positive"
            );
        }
        RbvmDecisionMethodologyPolicy methodology = runtime.findMethodology(revision).orElseThrow(() ->
                new ApiProblem(
                        404,
                        "DECISION_METHODOLOGY_NOT_FOUND",
                        "No registered Decision Methodology has the requested revision"
                ));
        return new Response(
                200,
                Map.of("ETag", methodologyEtag(methodology)),
                Map.of(
                        "contractId",
                        METHODOLOGY_CATALOG_CONTRACT_ID,
                        "methodology",
                        methodologyView(methodology)
                )
        );
    }

    public Response materialize(String contentType, InputStream input) throws IOException {
        requireJsonContentType(contentType);
        Map<String, Object> values;
        try {
            values = ManagedAssetApi.readJsonObject(input);
        } catch (ManagedAssetApi.ApiProblem problem) {
            int status = problem.status() == 413 ? 413 : 400;
            throw new ApiProblem(
                    status,
                    status == 413
                            ? "DECISION_INPUT_MATERIALIZATION_BODY_TOO_LARGE"
                            : "INVALID_DECISION_INPUT_MATERIALIZATION_REQUEST",
                    status == 413
                            ? "Decision Input materialization request body exceeds 16 KiB"
                            : "Decision Input materialization requires one valid flat UTF-8 JSON object"
            );
        }
        rejectUnknownFields(values);

        UUID findingId = requiredUuid(values, "findingId");
        int methodologyRevision = requiredPositiveInteger(values, "methodologyRevision");
        String methodologyPolicySha256 = requiredSha(values, "methodologyPolicySha256");
        Instant evaluatedAt = requiredInstant(values, "evaluatedAt");

        DecisionInputSnapshotMaterializationResult result;
        try {
            result = runtime.materialize(
                    findingId,
                    methodologyRevision,
                    methodologyPolicySha256,
                    evaluatedAt
            );
        } catch (DecisionInputRuntimeAccess.MethodologyNotFoundException exception) {
            throw new ApiProblem(
                    404,
                    "DECISION_METHODOLOGY_NOT_FOUND",
                    "The requested Decision Methodology revision is not registered"
            );
        } catch (DecisionInputRuntimeAccess.MethodologyIdentityMismatchException exception) {
            throw new ApiProblem(
                    409,
                    "DECISION_METHODOLOGY_IDENTITY_MISMATCH",
                    "The requested methodology revision and SHA do not identify the same registered policy"
            );
        } catch (DecisionInputRuntimeAccess.EvaluationConflictException exception) {
            throw new ApiProblem(
                    409,
                    "DECISION_INPUT_EVALUATION_CONFLICT",
                    "A different immutable Decision Input snapshot already exists for the exact Finding/methodology/evaluatedAt identity"
            );
        } catch (IllegalArgumentException exception) {
            throw new ApiProblem(
                    422,
                    "DECISION_INPUT_MATERIALIZATION_REJECTED",
                    exception.getMessage()
            );
        }

        DecisionInputSnapshotInstallResult.Status installStatus = result.installResult().status();
        int status = installStatus == DecisionInputSnapshotInstallResult.Status.INSERTED ? 201 : 200;
        RbvmDecisionInputSnapshot snapshot = result.snapshot();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractId", MATERIALIZATION_CONTRACT_ID);
        body.put("materializationStatus", installStatus.name());
        body.put("snapshot", snapshotView(snapshot));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("ETag", strongEtag(snapshot.snapshotSha256()));
        headers.put(
                "Location",
                "/api/v1/decision-input-snapshots/" + snapshot.snapshotSha256()
        );
        return new Response(status, headers, body);
    }

    static Map<String, Object> snapshotView(RbvmDecisionInputSnapshot snapshot) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("contractId", snapshot.contractId());
        output.put("semantics", snapshot.semantics());
        output.put("snapshotSha256", snapshot.snapshotSha256());
        output.put("findingId", snapshot.findingId().toString());
        output.put("methodologyRevision", snapshot.methodologyRevision());
        output.put("methodologyPolicySha256", snapshot.methodologyPolicySha256());
        output.put("evaluatedAt", snapshot.evaluatedAt().toString());
        output.put("canonicalPayloadFormat", snapshot.canonicalPayloadFormat());
        output.put(
                "canonicalPayloadBase64",
                Base64.getEncoder().encodeToString(snapshot.canonicalPayload())
        );
        output.put(
                "dimensions",
                java.util.Arrays.stream(EvidenceDimension.values())
                        .map(dimension -> dimensionView(snapshot.dimensions().get(dimension)))
                        .toList()
        );
        return output;
    }

    private static Map<String, Object> snapshotSummaryView(RbvmDecisionInputSnapshot snapshot) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("contractId", snapshot.contractId());
        output.put("snapshotSha256", snapshot.snapshotSha256());
        output.put("findingId", snapshot.findingId().toString());
        output.put("methodologyRevision", snapshot.methodologyRevision());
        output.put("methodologyPolicySha256", snapshot.methodologyPolicySha256());
        output.put("evaluatedAt", snapshot.evaluatedAt().toString());
        Map<String, String> states = new LinkedHashMap<>();
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            states.put(dimension.name(), snapshot.dimensions().get(dimension).state().name());
        }
        output.put("dimensionStates", states);
        return output;
    }

    private static Map<String, Object> dimensionView(DimensionInput input) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("dimension", input.dimension().name());
        output.put("state", input.state().name());
        output.put(
                "evidenceReferences",
                input.evidenceReferences().stream()
                        .map(DecisionInputApi::evidenceReferenceView)
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

    private static Map<String, Object> methodologyView(RbvmDecisionMethodologyPolicy methodology) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("contractId", methodology.contractId());
        output.put("semantics", methodology.semantics());
        output.put("revision", methodology.revision());
        output.put("policySha256", methodology.policySha256());
        output.put("subjectScope", methodology.subjectScope().name());
        output.put("missingEvidenceHandling", methodology.missingEvidenceHandling().name());
        output.put("ambiguityHandling", methodology.ambiguityHandling().name());
        output.put("legacyPriorityHandling", methodology.legacyPriorityHandling().name());
        output.put(
                "canonicalPayloadFormat",
                RbvmDecisionMethodologyPolicy.CANONICAL_PAYLOAD_FORMAT
        );
        output.put(
                "canonicalPayloadBase64",
                Base64.getEncoder().encodeToString(methodology.canonicalPayload())
        );
        output.put(
                "evidencePolicies",
                java.util.Arrays.stream(EvidenceDimension.values())
                        .map(dimension -> methodologyPolicyView(
                                methodology.evidencePolicies().get(dimension)
                        ))
                        .toList()
        );
        return output;
    }

    private static Map<String, Object> methodologyPolicyView(EvidenceSelectionPolicy policy) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("dimension", policy.dimension().name());
        output.put("sourceSelectionMode", policy.sourceSelectionMode().name());
        output.put("sourceAllowlist", policy.sourceAllowlist());
        output.put("freshnessMode", policy.freshnessMode().name());
        output.put("maximumAgeSeconds", policy.maximumAgeSeconds());
        return output;
    }

    static String strongEtag(String snapshotSha256) {
        return "\"decision-input-" + requireSha(snapshotSha256, "snapshotSha256") + "\"";
    }

    private static String methodologyEtag(RbvmDecisionMethodologyPolicy methodology) {
        return "\"decision-methodology-r" + methodology.revision() + '-'
                + methodology.policySha256() + "\"";
    }

    static String requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new ApiProblem(
                    400,
                    "INVALID_DECISION_INPUT_IDENTITY",
                    field + " must be a lowercase SHA-256"
            );
        }
        return value;
    }

    private static void requireJsonContentType(String contentType) {
        if (contentType == null
                || !contentType.split(";", 2)[0].trim().equalsIgnoreCase("application/json")) {
            throw new ApiProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be application/json"
            );
        }
    }

    private static void rejectUnknownFields(Map<String, Object> values) {
        for (String field : values.keySet()) {
            if (!MATERIALIZATION_FIELDS.contains(field)) {
                throw new ApiProblem(
                        400,
                        "UNKNOWN_DECISION_INPUT_MATERIALIZATION_FIELDS",
                        "Unknown request field: " + field
                );
            }
        }
        for (String field : MATERIALIZATION_FIELDS) {
            if (!values.containsKey(field)) {
                throw new ApiProblem(
                        422,
                        "DECISION_INPUT_MATERIALIZATION_REJECTED",
                        field + " is required"
                );
            }
        }
    }

    private static String requiredString(Map<String, Object> values, String field) {
        Object value = values.get(field);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new ApiProblem(
                    422,
                    "DECISION_INPUT_MATERIALIZATION_REJECTED",
                    field + " must be a non-empty string"
            );
        }
        return text.trim();
    }

    private static UUID requiredUuid(Map<String, Object> values, String field) {
        String text = requiredString(values, field);
        try {
            UUID parsed = UUID.fromString(text);
            if (!parsed.toString().equals(text.toLowerCase(Locale.ROOT))) {
                throw new IllegalArgumentException("non-canonical UUID");
            }
            return parsed;
        } catch (IllegalArgumentException exception) {
            throw new ApiProblem(
                    422,
                    "DECISION_INPUT_MATERIALIZATION_REJECTED",
                    field + " must be a canonical UUID"
            );
        }
    }

    private static int requiredPositiveInteger(Map<String, Object> values, String field) {
        Object value = values.get(field);
        if (!(value instanceof Long number)
                || number < 1
                || number > Integer.MAX_VALUE) {
            throw new ApiProblem(
                    422,
                    "DECISION_INPUT_MATERIALIZATION_REJECTED",
                    field + " must be a positive integer"
            );
        }
        return number.intValue();
    }

    private static String requiredSha(Map<String, Object> values, String field) {
        String value = requiredString(values, field);
        if (!value.matches("[a-f0-9]{64}")) {
            throw new ApiProblem(
                    422,
                    "DECISION_INPUT_MATERIALIZATION_REJECTED",
                    field + " must be a lowercase SHA-256"
            );
        }
        return value;
    }

    private static Instant requiredInstant(Map<String, Object> values, String field) {
        String value = requiredString(values, field);
        try {
            Instant parsed = Instant.parse(value);
            if (!parsed.toString().equals(value)) {
                throw new DateTimeException("non-canonical Instant") { };
            }
            return parsed;
        } catch (DateTimeException exception) {
            throw new ApiProblem(
                    422,
                    "DECISION_INPUT_MATERIALIZATION_REJECTED",
                    field + " must be a canonical UTC Instant"
            );
        }
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

        public int status() {
            return status;
        }

        public String code() {
            return code;
        }
    }
}
