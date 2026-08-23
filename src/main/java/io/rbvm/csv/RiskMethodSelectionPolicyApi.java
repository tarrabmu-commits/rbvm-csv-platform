package io.rbvm.csv;

import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy.MethodFamily;
import io.rbvm.postgres.RiskMethodSelectionPolicyInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyStore;

import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Exact-identity control-plane API for immutable primary risk-method policy revisions. */
public final class RiskMethodSelectionPolicyApi {
    public static final String CONTRACT_ID = "RBVM_RISK_METHOD_SELECTION_POLICY_API_V1";
    public static final String INSTALLATION_CONTRACT_ID =
            "RBVM_RISK_METHOD_SELECTION_POLICY_INSTALLATION_API_V1";

    private final RiskMethodSelectionPolicyStore policies;

    public RiskMethodSelectionPolicyApi(RiskMethodSelectionPolicyStore policies) {
        this.policies = Objects.requireNonNull(policies, "policies");
    }

    /** Exact lookup requires both immutable policy revision and canonical policy SHA. */
    public Response get(int revision, String policySha256) throws IOException {
        int exactRevision = requireRevision(revision);
        String exactSha = requireSha(policySha256, "policySha256");
        RbvmRiskMethodSelectionPolicy policy = policies.findByRevision(exactRevision)
                .filter(candidate -> candidate.policySha256().equals(exactSha))
                .orElseThrow(() -> new ApiProblem(
                        404,
                        "RISK_METHOD_SELECTION_POLICY_NOT_FOUND",
                        "No persisted risk method selection policy matches the exact revision and SHA"
                ));
        return response(200, policy, null);
    }

    /**
     * Installs one immutable policy revision from an explicit exact method identity. No family or
     * catalog entry is selected implicitly.
     */
    public Response install(
            int revision,
            String methodFamily,
            String methodId,
            int methodVersion,
            String methodSha256
    ) throws IOException {
        int exactRevision = requireRevision(revision);
        MethodFamily family = requireFamily(methodFamily);
        String exactMethodId = requireText(methodId, "methodId");
        int exactMethodVersion = requireMethodVersion(methodVersion);
        String exactMethodSha = requireSha(methodSha256, "methodSha256");

        RbvmRiskMethodSelectionPolicy policy = switch (family) {
            case RBVM_FORMULA -> requireFormulaIdentity(
                    exactRevision,
                    exactMethodId,
                    exactMethodVersion,
                    exactMethodSha
            );
            case STANDARD_DERIVED -> requireDerivedIdentity(
                    exactRevision,
                    exactMethodId,
                    exactMethodVersion,
                    exactMethodSha
            );
        };

        RiskMethodSelectionPolicyInstallResult result = policies.install(policy);
        if (result.status() == RiskMethodSelectionPolicyInstallResult.Status.REVISION_CONFLICT) {
            throw new ApiProblem(
                    409,
                    "RISK_METHOD_SELECTION_POLICY_REVISION_CONFLICT",
                    "The requested revision is already bound to a different immutable policy identity"
            );
        }
        int status = result.status() == RiskMethodSelectionPolicyInstallResult.Status.INSERTED
                ? 201
                : 200;
        return response(status, policy, result.status().name());
    }

    private static RbvmRiskMethodSelectionPolicy requireFormulaIdentity(
            int revision,
            String methodId,
            int methodVersion,
            String methodSha256
    ) {
        if (!methodId.equals(RbvmFormulaV1.FORMULA_ID)
                || methodVersion != RbvmFormulaV1.FORMULA_VERSION
                || !methodSha256.equals(RbvmFormulaV1.FORMULA_SHA256)) {
            throw new ApiProblem(
                    404,
                    "RISK_METHOD_NOT_FOUND",
                    "No accepted RBVM Formula matches the requested exact identity"
            );
        }
        return RbvmRiskMethodSelectionPolicy.formulaV1(revision);
    }

    private static RbvmRiskMethodSelectionPolicy requireDerivedIdentity(
            int revision,
            String methodId,
            int methodVersion,
            String methodSha256
    ) {
        RbvmDerivedRiskMethodology methodology = RbvmDerivedRiskMethodologyCatalog.find(methodId)
                .orElseThrow(() -> new ApiProblem(
                        404,
                        "RISK_METHOD_NOT_FOUND",
                        "No implemented standard-derived methodology matches the requested exact identity"
                ));
        RbvmDerivedRiskMethodology.Definition definition = methodology.definition();
        if (!definition.methodologyId().equals(methodId)
                || definition.version() != methodVersion
                || !definition.methodologySha256().equals(methodSha256)) {
            throw new ApiProblem(
                    404,
                    "RISK_METHOD_NOT_FOUND",
                    "No implemented standard-derived methodology matches the requested exact identity"
            );
        }
        return RbvmRiskMethodSelectionPolicy.derived(revision, definition);
    }

    private static Response response(
            int status,
            RbvmRiskMethodSelectionPolicy policy,
            String installationStatus
    ) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put(
                "contractId",
                installationStatus == null ? CONTRACT_ID : INSTALLATION_CONTRACT_ID
        );
        if (installationStatus != null) {
            body.put("installationStatus", installationStatus);
        }
        body.put("selectionSemantics", "EXACT_REVISION_AND_SHA_NO_CURRENT_LATEST_OR_DEFAULT");
        body.put("policy", policyView(policy));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("ETag", strongEtag(policy.policySha256()));
        headers.put("Location", location(policy));
        return new Response(status, headers, body);
    }

    private static Map<String, Object> policyView(RbvmRiskMethodSelectionPolicy policy) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("policyContractId", policy.contractId());
        output.put("semantics", policy.semantics());
        output.put("revision", policy.revision());
        output.put("policySha256", policy.policySha256());
        output.put("selectionRole", policy.selectionRole().name());
        output.put("methodFamily", policy.methodFamily().name());
        output.put("methodId", policy.methodId());
        output.put("methodVersion", policy.methodVersion());
        output.put("methodSha256", policy.methodSha256());
        output.put("canonicalPayloadFormat", RbvmRiskMethodSelectionPolicy.CANONICAL_PAYLOAD_FORMAT);
        output.put(
                "canonicalPayloadBase64",
                Base64.getEncoder().encodeToString(policy.canonicalPayload())
        );
        return output;
    }

    static String location(RbvmRiskMethodSelectionPolicy policy) {
        return "/api/v1/risk-method-selection-policies/"
                + policy.revision() + "/" + policy.policySha256();
    }

    static String strongEtag(String policySha256) {
        return "\"risk-method-selection-policy-"
                + requireSha(policySha256, "policySha256") + "\"";
    }

    static int requireRevision(int revision) {
        if (revision < 1) {
            throw new ApiProblem(
                    400,
                    "INVALID_RISK_METHOD_SELECTION_POLICY_IDENTITY",
                    "revision must be a positive integer"
            );
        }
        return revision;
    }

    static int requireMethodVersion(int version) {
        if (version < 1) {
            throw new ApiProblem(
                    400,
                    "INVALID_RISK_METHOD_SELECTION_POLICY_IDENTITY",
                    "methodVersion must be a positive integer"
            );
        }
        return version;
    }

    static MethodFamily requireFamily(String value) {
        String family = requireText(value, "methodFamily");
        try {
            return MethodFamily.valueOf(family);
        } catch (IllegalArgumentException exception) {
            throw new ApiProblem(
                    400,
                    "INVALID_RISK_METHOD_SELECTION_POLICY_IDENTITY",
                    "methodFamily must be RBVM_FORMULA or STANDARD_DERIVED"
            );
        }
    }

    static String requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new ApiProblem(
                    400,
                    "INVALID_RISK_METHOD_SELECTION_POLICY_IDENTITY",
                    field + " must be lowercase SHA-256"
            );
        }
        return value;
    }

    static String requireText(String value, String field) {
        if (value == null || value.isBlank() || value.indexOf('\u0000') >= 0
                || !value.equals(value.trim())) {
            throw new ApiProblem(
                    400,
                    "INVALID_RISK_METHOD_SELECTION_POLICY_IDENTITY",
                    field + " must be non-empty canonical text"
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
