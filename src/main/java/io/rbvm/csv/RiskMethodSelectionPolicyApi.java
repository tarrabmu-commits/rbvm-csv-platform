package io.rbvm.csv;

import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy.MethodFamily;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;
import io.rbvm.postgres.RiskMethodSelectionPolicyActivationInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyActivationStore;
import io.rbvm.postgres.RiskMethodSelectionPolicyInstallResult;
import io.rbvm.postgres.RiskMethodSelectionPolicyStore;

import java.io.IOException;
import java.time.Instant;
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
    public static final String ACTIVATION_CONTRACT_ID =
            "RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_API_V1";
    public static final String ACTIVATION_INSTALLATION_CONTRACT_ID =
            "RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_INSTALLATION_API_V1";
    public static final String ACTIVATION_SELECTION_SEMANTICS =
            "CURRENT_IS_GREATEST_EXPLICIT_ACTIVATION_REVISION_NEVER_POLICY_REVISION";

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

    /** Returns the greatest explicit activation event; never-installed is not synthesized as CLEARED. */
    public Response currentActivation() throws IOException {
        RbvmRiskMethodSelectionPolicyActivationEvent event = activationStore().current()
                .orElseThrow(() -> new ApiProblem(
                        404,
                        "RISK_METHOD_SELECTION_POLICY_ACTIVATION_NOT_FOUND",
                        "No explicit risk method selection policy activation event has been persisted"
                ));
        return activationResponse(200, event, null);
    }

    /** Exact activation lookup requires both activation revision and canonical event SHA. */
    public Response getActivation(int activationRevision, String eventSha256) throws IOException {
        int exactRevision = requireActivationRevision(activationRevision);
        String exactSha = requireSha(eventSha256, "eventSha256");
        RbvmRiskMethodSelectionPolicyActivationEvent event = activationStore()
                .findByActivationRevision(exactRevision)
                .filter(candidate -> candidate.eventSha256().equals(exactSha))
                .orElseThrow(() -> new ApiProblem(
                        404,
                        "RISK_METHOD_SELECTION_POLICY_ACTIVATION_NOT_FOUND",
                        "No persisted activation event matches the exact activation revision and event SHA"
                ));
        return activationResponse(200, event, null);
    }

    /**
     * Appends or exactly replays one ACTIVE event. The authenticated actor and explicit recordedAt
     * are part of canonical event identity; policy selection is exact revision+SHA only.
     */
    public Response activate(
            int activationRevision,
            int policyRevision,
            String policySha256,
            String changedBy,
            Instant recordedAt
    ) throws IOException {
        int exactActivationRevision = requireActivationRevision(activationRevision);
        int exactPolicyRevision = requireRevision(policyRevision);
        String exactPolicySha = requireSha(policySha256, "policySha256");
        String actor = requireText(changedBy, "changedBy");
        Instant exactRecordedAt = Objects.requireNonNull(recordedAt, "recordedAt");

        RbvmRiskMethodSelectionPolicy policy = policies.findByRevision(exactPolicyRevision)
                .filter(candidate -> candidate.policySha256().equals(exactPolicySha))
                .orElseThrow(() -> new ApiProblem(
                        404,
                        "RISK_METHOD_SELECTION_POLICY_NOT_FOUND",
                        "The exact policy revision and SHA requested for activation do not exist"
                ));
        RbvmRiskMethodSelectionPolicyActivationEvent event =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        exactActivationRevision,
                        policy,
                        actor,
                        "",
                        exactRecordedAt
                );
        return installActivation(event);
    }

    /** Appends or exactly replays one explicit CLEARED event. */
    public Response clearActivation(
            int activationRevision,
            String changedBy,
            Instant recordedAt
    ) throws IOException {
        int exactActivationRevision = requireActivationRevision(activationRevision);
        String actor = requireText(changedBy, "changedBy");
        Instant exactRecordedAt = Objects.requireNonNull(recordedAt, "recordedAt");
        RbvmRiskMethodSelectionPolicyActivationEvent event =
                RbvmRiskMethodSelectionPolicyActivationEvent.clear(
                        exactActivationRevision,
                        actor,
                        "",
                        exactRecordedAt
                );
        return installActivation(event);
    }

    private Response installActivation(RbvmRiskMethodSelectionPolicyActivationEvent event)
            throws IOException {
        RiskMethodSelectionPolicyActivationInstallResult result = activationStore().install(event);
        switch (result.status()) {
            case REVISION_CONFLICT -> throw new ApiProblem(
                    409,
                    "RISK_METHOD_SELECTION_POLICY_ACTIVATION_REVISION_CONFLICT",
                    "The requested activation revision is already bound to a different immutable activation event"
            );
            case STALE_ACTIVATION_REVISION -> throw new ApiProblem(
                    409,
                    "STALE_RISK_METHOD_SELECTION_POLICY_ACTIVATION_REVISION",
                    "The requested activation revision is older than the current explicit activation revision "
                            + result.observedActivationRevision()
            );
            case INSERTED, REPLAYED -> {
                int status = result.status()
                        == RiskMethodSelectionPolicyActivationInstallResult.Status.INSERTED ? 201 : 200;
                return activationResponse(status, event, result.status().name());
            }
        }
        throw new IllegalStateException("Unhandled activation install status " + result.status());
    }

    private RiskMethodSelectionPolicyActivationStore activationStore() {
        return policies.activationStore().orElseThrow(() -> new ApiProblem(
                503,
                "RISK_METHOD_SELECTION_POLICY_ACTIVATION_PERSISTENCE_UNAVAILABLE",
                "Risk Method Selection Policy activation requires PostgreSQL schema version 26 or newer"
        ));
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

    private static Response activationResponse(
            int status,
            RbvmRiskMethodSelectionPolicyActivationEvent event,
            String installationStatus
    ) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put(
                "contractId",
                installationStatus == null ? ACTIVATION_CONTRACT_ID : ACTIVATION_INSTALLATION_CONTRACT_ID
        );
        if (installationStatus != null) body.put("installationStatus", installationStatus);
        body.put("activationSemantics", ACTIVATION_SELECTION_SEMANTICS);
        body.put("activation", activationView(event));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("ETag", activationStrongEtag(event.eventSha256()));
        headers.put("Location", activationLocation(event));
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

    private static Map<String, Object> activationView(
            RbvmRiskMethodSelectionPolicyActivationEvent event
    ) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("activationContractId", event.contractId());
        output.put("semantics", event.semantics());
        output.put("activationRevision", event.activationRevision());
        output.put("activationState", event.activationState().name());
        output.put("policyRevision", event.policyRevision());
        output.put("policySha256", event.policySha256());
        output.put("changedBy", event.changedBy());
        output.put("changeNote", event.changeNote());
        output.put("recordedAt", event.recordedAt().toString());
        output.put("eventSha256", event.eventSha256());
        output.put(
                "canonicalPayloadFormat",
                RbvmRiskMethodSelectionPolicyActivationEvent.CANONICAL_PAYLOAD_FORMAT
        );
        output.put(
                "canonicalPayloadBase64",
                Base64.getEncoder().encodeToString(event.canonicalPayload())
        );
        return output;
    }

    static String location(RbvmRiskMethodSelectionPolicy policy) {
        return "/api/v1/risk-method-selection-policies/"
                + policy.revision() + "/" + policy.policySha256();
    }

    static String activationLocation(RbvmRiskMethodSelectionPolicyActivationEvent event) {
        return "/api/v1/risk-method-selection-policy-activations/"
                + event.activationRevision() + "/" + event.eventSha256();
    }

    static String strongEtag(String policySha256) {
        return "\"risk-method-selection-policy-"
                + requireSha(policySha256, "policySha256") + "\"";
    }

    static String activationStrongEtag(String eventSha256) {
        return "\"risk-method-selection-policy-activation-"
                + requireSha(eventSha256, "eventSha256") + "\"";
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

    static int requireActivationRevision(int revision) {
        if (revision < 1) {
            throw new ApiProblem(
                    400,
                    "INVALID_RISK_METHOD_SELECTION_POLICY_ACTIVATION_IDENTITY",
                    "activationRevision must be a positive integer"
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
