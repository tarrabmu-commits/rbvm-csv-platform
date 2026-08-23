package io.rbvm.decision;

import io.rbvm.decision.RbvmRiskMethodSelectionPolicy.MethodFamily;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy.SelectionRole;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Immutable provenance binding from one exact ACTIVE risk-method activation to one exact result.
 *
 * <p>This object never represents "current". The activation revision and event SHA are exact
 * historical identity; the referenced policy and Decision Input are exact immutable identities;
 * and the result SHA is the canonical identity emitted by the selected method's native result
 * contract. The binding carries no score, Priority, Treatment, SLA, or remediation semantic.</p>
 */
public final class RbvmActiveRiskMethodExecutionBinding {
    public static final String ID = "RBVM_ACTIVE_RISK_METHOD_EXECUTION_BINDING_V1";
    public static final String SEMANTICS =
            "EXACT_ACTIVATION_EVENT_EXACT_POLICY_EXACT_PRIMARY_METHOD_EXACT_DECISION_INPUT_EXACT_RESULT";
    public static final String CANONICAL_PAYLOAD_FORMAT =
            "RBVM_ACTIVE_RISK_METHOD_EXECUTION_BINDING_CANONICAL_BINARY_V1";

    private final int activationRevision;
    private final String activationEventSha256;
    private final int policyRevision;
    private final String policySha256;
    private final SelectionRole selectionRole;
    private final MethodFamily methodFamily;
    private final String methodId;
    private final int methodVersion;
    private final String methodSha256;
    private final String inputSnapshotSha256;
    private final ResultFamily resultFamily;
    private final String resultSha256;
    private final byte[] canonicalPayload;
    private final String bindingSha256;

    private RbvmActiveRiskMethodExecutionBinding(
            int activationRevision,
            String activationEventSha256,
            int policyRevision,
            String policySha256,
            SelectionRole selectionRole,
            MethodFamily methodFamily,
            String methodId,
            int methodVersion,
            String methodSha256,
            String inputSnapshotSha256,
            ResultFamily resultFamily,
            String resultSha256,
            String expectedBindingSha256
    ) {
        if (activationRevision < 1) {
            throw new IllegalArgumentException("activationRevision must be positive");
        }
        requireSha(activationEventSha256, "activationEventSha256");
        if (policyRevision < 1) {
            throw new IllegalArgumentException("policyRevision must be positive");
        }
        requireSha(policySha256, "policySha256");
        if (selectionRole != SelectionRole.PRIMARY) {
            throw new IllegalArgumentException("execution binding supports PRIMARY selection only");
        }
        this.selectionRole = selectionRole;
        this.methodFamily = Objects.requireNonNull(methodFamily, "methodFamily");
        this.methodId = requireText(methodId, "methodId");
        if (methodVersion < 1) {
            throw new IllegalArgumentException("methodVersion must be positive");
        }
        requireSha(methodSha256, "methodSha256");
        requireSha(inputSnapshotSha256, "inputSnapshotSha256");
        this.resultFamily = Objects.requireNonNull(resultFamily, "resultFamily");
        requireSha(resultSha256, "resultSha256");
        requireFamilyShape(methodFamily, resultFamily);

        this.activationRevision = activationRevision;
        this.activationEventSha256 = activationEventSha256;
        this.policyRevision = policyRevision;
        this.policySha256 = policySha256;
        this.methodVersion = methodVersion;
        this.methodSha256 = methodSha256;
        this.inputSnapshotSha256 = inputSnapshotSha256;
        this.resultSha256 = resultSha256;
        this.canonicalPayload = canonicalPayloadBytes();
        this.bindingSha256 = sha256(canonicalPayload);
        if (expectedBindingSha256 != null && !bindingSha256.equals(expectedBindingSha256)) {
            throw new IllegalArgumentException(
                    "bindingSha256 does not match canonical execution binding payload");
        }
    }

    /**
     * Creates a new execution binding from one exact ACTIVE activation and its exact persisted
     * policy. The policy must still be executable in the current catalog at execution time.
     */
    public static RbvmActiveRiskMethodExecutionBinding bind(
            RbvmRiskMethodSelectionPolicyActivationEvent activation,
            RbvmRiskMethodSelectionPolicy policy,
            String inputSnapshotSha256,
            ResultFamily resultFamily,
            String resultSha256
    ) {
        Objects.requireNonNull(activation, "activation");
        Objects.requireNonNull(policy, "policy").requireCatalogBound();
        if (!activation.activatesPolicy()) {
            throw new IllegalArgumentException("execution binding requires an explicit ACTIVE event");
        }
        if (!Objects.equals(activation.policyRevision(), policy.revision())
                || !activation.policySha256().equals(policy.policySha256())) {
            throw new IllegalArgumentException(
                    "activation event does not reference the supplied exact policy identity");
        }
        return new RbvmActiveRiskMethodExecutionBinding(
                activation.activationRevision(),
                activation.eventSha256(),
                policy.revision(),
                policy.policySha256(),
                policy.selectionRole(),
                policy.methodFamily(),
                policy.methodId(),
                policy.methodVersion(),
                policy.methodSha256(),
                inputSnapshotSha256,
                resultFamily,
                resultSha256,
                null
        );
    }

    /** Historical rehydration verifies canonical identity without consulting today's catalog. */
    public static RbvmActiveRiskMethodExecutionBinding rehydrate(
            int activationRevision,
            String activationEventSha256,
            int policyRevision,
            String policySha256,
            SelectionRole selectionRole,
            MethodFamily methodFamily,
            String methodId,
            int methodVersion,
            String methodSha256,
            String inputSnapshotSha256,
            ResultFamily resultFamily,
            String resultSha256,
            String bindingSha256
    ) {
        requireSha(bindingSha256, "bindingSha256");
        return new RbvmActiveRiskMethodExecutionBinding(
                activationRevision,
                activationEventSha256,
                policyRevision,
                policySha256,
                selectionRole,
                methodFamily,
                methodId,
                methodVersion,
                methodSha256,
                inputSnapshotSha256,
                resultFamily,
                resultSha256,
                bindingSha256
        );
    }

    private byte[] canonicalPayloadBytes() {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                output.writeUTF(ID);
                output.writeUTF(SEMANTICS);
                output.writeInt(activationRevision);
                output.writeUTF(activationEventSha256);
                output.writeInt(policyRevision);
                output.writeUTF(policySha256);
                output.writeUTF(selectionRole.name());
                output.writeUTF(methodFamily.name());
                output.writeUTF(methodId);
                output.writeInt(methodVersion);
                output.writeUTF(methodSha256);
                output.writeUTF(inputSnapshotSha256);
                output.writeUTF(resultFamily.name());
                output.writeUTF(resultSha256);
            }
            return buffer.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException(
                    "Could not canonicalize in-memory active risk method execution binding",
                    impossible
            );
        }
    }

    public String contractId() { return ID; }
    public String semantics() { return SEMANTICS; }
    public int activationRevision() { return activationRevision; }
    public String activationEventSha256() { return activationEventSha256; }
    public int policyRevision() { return policyRevision; }
    public String policySha256() { return policySha256; }
    public SelectionRole selectionRole() { return selectionRole; }
    public MethodFamily methodFamily() { return methodFamily; }
    public String methodId() { return methodId; }
    public int methodVersion() { return methodVersion; }
    public String methodSha256() { return methodSha256; }
    public String inputSnapshotSha256() { return inputSnapshotSha256; }
    public ResultFamily resultFamily() { return resultFamily; }
    public String resultSha256() { return resultSha256; }
    public byte[] canonicalPayload() { return canonicalPayload.clone(); }
    public String bindingSha256() { return bindingSha256; }

    public enum ResultFamily {
        RBVM_FORMULA_RESULT,
        DERIVED_RISK_RESULT
    }

    private static void requireFamilyShape(MethodFamily methodFamily, ResultFamily resultFamily) {
        if (methodFamily == MethodFamily.RBVM_FORMULA
                && resultFamily != ResultFamily.RBVM_FORMULA_RESULT) {
            throw new IllegalArgumentException(
                    "RBVM_FORMULA policy must bind an RBVM_FORMULA_RESULT");
        }
        if (methodFamily == MethodFamily.STANDARD_DERIVED
                && resultFamily != ResultFamily.DERIVED_RISK_RESULT) {
            throw new IllegalArgumentException(
                    "STANDARD_DERIVED policy must bind a DERIVED_RISK_RESULT");
        }
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank() || !value.equals(value.trim())
                || value.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " must be non-empty canonical text");
        }
        return value;
    }

    private static void requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }
}
