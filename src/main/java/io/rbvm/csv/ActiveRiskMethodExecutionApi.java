package io.rbvm.csv;

import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding;
import io.rbvm.postgres.ActiveRiskMethodExecutionBindingMaterializationResult;
import io.rbvm.postgres.ActiveRiskMethodExecutionBindingStore;
import io.rbvm.postgres.DefaultActiveRiskMethodExecutionBindingMaterializer;
import io.rbvm.postgres.DefaultDerivedRiskResultMaterializer;
import io.rbvm.postgres.DefaultFormulaResultMaterializer;

import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Exact-identity API for V27 active-risk-method execution and immutable binding replay. */
public final class ActiveRiskMethodExecutionApi {
    public static final String CONTRACT_ID = "RBVM_ACTIVE_RISK_METHOD_EXECUTION_API_V1";
    public static final String EXECUTION_SEMANTICS =
            "EXPLICIT_ACTIVATION_REVISION_EVENT_SHA_AND_DECISION_INPUT_SHA_ONLY_NO_CURRENT_DEFAULT";

    private final ActiveRiskMethodExecutionBindingStore bindings;
    private final DefaultActiveRiskMethodExecutionBindingMaterializer materializer;

    public ActiveRiskMethodExecutionApi(
            ActiveRiskMethodExecutionBindingStore bindings,
            DefaultActiveRiskMethodExecutionBindingMaterializer materializer
    ) {
        this.bindings = Objects.requireNonNull(bindings, "bindings");
        this.materializer = Objects.requireNonNull(materializer, "materializer");
    }

    /** Exact immutable read by canonical execution-binding SHA. */
    public Response getBinding(String bindingSha256) throws IOException {
        String sha = requireSha(bindingSha256, "bindingSha256");
        RbvmActiveRiskMethodExecutionBinding binding = bindings.findByBindingSha256(sha)
                .orElseThrow(() -> new ApiProblem(
                        404,
                        "ACTIVE_RISK_METHOD_EXECUTION_BINDING_NOT_FOUND",
                        "No execution binding has the requested exact canonical identity"
                ));
        return response(200, null, binding);
    }

    /**
     * Execute only one explicit historical activation identity against one explicit Decision Input.
     * There is deliberately no current/latest/default execution entry point.
     */
    public Response execute(
            int activationRevision,
            String activationEventSha256,
            String inputSnapshotSha256
    ) throws IOException {
        if (activationRevision < 1) {
            throw new ApiProblem(
                    400,
                    "INVALID_ACTIVE_RISK_METHOD_EXECUTION_IDENTITY",
                    "activationRevision must be positive"
            );
        }
        String eventSha = requireSha(activationEventSha256, "activationEventSha256");
        String inputSha = requireSha(inputSnapshotSha256, "inputSnapshotSha256");

        ActiveRiskMethodExecutionBindingMaterializationResult result;
        try {
            result = materializer.materialize(activationRevision, eventSha, inputSha);
        } catch (DefaultActiveRiskMethodExecutionBindingMaterializer.ActivationPersistenceUnavailableException exception) {
            throw new ApiProblem(
                    503,
                    "ACTIVE_RISK_METHOD_EXECUTION_RUNTIME_UNAVAILABLE",
                    "Risk Method Selection Policy activation persistence is unavailable"
            );
        } catch (DefaultActiveRiskMethodExecutionBindingMaterializer.ActivationNotFoundException exception) {
            throw new ApiProblem(
                    404,
                    "RISK_METHOD_SELECTION_ACTIVATION_NOT_FOUND",
                    "No activation event matches the exact activation revision and event SHA"
            );
        } catch (DefaultActiveRiskMethodExecutionBindingMaterializer.ExplicitlyClearedActivationException exception) {
            throw new ApiProblem(
                    409,
                    "RISK_METHOD_SELECTION_ACTIVATION_CLEARED",
                    "The exact activation event explicitly clears the active risk method and cannot execute"
            );
        } catch (DefaultActiveRiskMethodExecutionBindingMaterializer.SelectedMethodUnavailableException exception) {
            throw new ApiProblem(
                    409,
                    "SELECTED_RISK_METHOD_UNAVAILABLE",
                    "The exact selected historical method is not executable in the current catalog"
            );
        } catch (DefaultFormulaResultMaterializer.SnapshotNotFoundException
                 | DefaultDerivedRiskResultMaterializer.SnapshotNotFoundException exception) {
            throw new ApiProblem(
                    404,
                    "DECISION_INPUT_SNAPSHOT_NOT_FOUND",
                    "No persisted Decision Input snapshot has the requested exact identity"
            );
        } catch (DefaultFormulaResultMaterializer.UnsupportedSnapshotContractException
                 | DefaultDerivedRiskResultMaterializer.UnsupportedSnapshotContractException exception) {
            throw new ApiProblem(
                    422,
                    "ACTIVE_RISK_METHOD_EXECUTION_REQUIRES_DECISION_INPUT_V3",
                    "Active risk method execution accepts only a persisted Decision Input Snapshot V3"
            );
        } catch (DefaultFormulaResultMaterializer.ResultConflictException
                 | DefaultDerivedRiskResultMaterializer.ResultConflictException
                 | DefaultActiveRiskMethodExecutionBindingMaterializer.ExecutionBindingConflictException exception) {
            throw new ApiProblem(
                    409,
                    "ACTIVE_RISK_METHOD_EXECUTION_CONFLICT",
                    "A conflicting immutable native result or execution binding already exists"
            );
        } catch (DefaultActiveRiskMethodExecutionBindingMaterializer.PolicyIntegrityFailureException
                 | DefaultActiveRiskMethodExecutionBindingMaterializer.ExecutionBindingIntegrityFailureException exception) {
            throw new ApiProblem(
                    500,
                    "ACTIVE_RISK_METHOD_EXECUTION_INTEGRITY_FAILURE",
                    "Persisted activation, policy, method, input, or result identities failed exact integrity verification"
            );
        }

        int status = result.installResult().status()
                == io.rbvm.postgres.ActiveRiskMethodExecutionBindingInstallResult.Status.INSERTED
                ? 201 : 200;
        return response(status, result.installResult().status().name(), result.binding());
    }

    private static Response response(
            int status,
            String executionStatus,
            RbvmActiveRiskMethodExecutionBinding binding
    ) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractId", CONTRACT_ID);
        body.put("executionSemantics", EXECUTION_SEMANTICS);
        if (executionStatus != null) body.put("executionStatus", executionStatus);
        body.put("binding", bindingView(binding));
        body.put("resultLocation", resultLocation(binding));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("ETag", strongEtag(binding.bindingSha256()));
        headers.put(
                "Location",
                "/api/v1/active-risk-method-execution-bindings/" + binding.bindingSha256()
        );
        return new Response(status, headers, body);
    }

    private static Map<String, Object> bindingView(RbvmActiveRiskMethodExecutionBinding binding) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("contractId", binding.contractId());
        output.put("semantics", binding.semantics());
        output.put("canonicalPayloadFormat", RbvmActiveRiskMethodExecutionBinding.CANONICAL_PAYLOAD_FORMAT);
        output.put("bindingSha256", binding.bindingSha256());
        output.put(
                "canonicalPayloadBase64",
                Base64.getEncoder().encodeToString(binding.canonicalPayload())
        );
        output.put("activationRevision", binding.activationRevision());
        output.put("activationEventSha256", binding.activationEventSha256());
        output.put("policyRevision", binding.policyRevision());
        output.put("policySha256", binding.policySha256());
        output.put("selectionRole", binding.selectionRole().name());
        output.put("methodFamily", binding.methodFamily().name());
        output.put("methodId", binding.methodId());
        output.put("methodVersion", binding.methodVersion());
        output.put("methodSha256", binding.methodSha256());
        output.put("inputSnapshotSha256", binding.inputSnapshotSha256());
        output.put("resultFamily", binding.resultFamily().name());
        output.put("resultSha256", binding.resultSha256());
        return Collections.unmodifiableMap(output);
    }

    private static String resultLocation(RbvmActiveRiskMethodExecutionBinding binding) {
        return switch (binding.resultFamily()) {
            case RBVM_FORMULA_RESULT -> "/api/v1/formula-results/" + binding.resultSha256();
            case DERIVED_RISK_RESULT -> "/api/v1/derived-risk-results/" + binding.resultSha256();
        };
    }

    static String strongEtag(String bindingSha256) {
        return "\"active-risk-method-execution-binding-"
                + requireSha(bindingSha256, "bindingSha256") + "\"";
    }

    private static String requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new ApiProblem(
                    400,
                    "INVALID_ACTIVE_RISK_METHOD_EXECUTION_IDENTITY",
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
