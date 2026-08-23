package io.rbvm.decision;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Immutable tenant-scoped activation event for one exact Risk Method Selection Policy identity.
 *
 * <p>Activation revision orders explicit activation events only. It never orders or selects policy
 * revisions. ACTIVE references one exact persisted policy revision+SHA; CLEARED explicitly records
 * that no policy is active.</p>
 */
public final class RbvmRiskMethodSelectionPolicyActivationEvent {
    public static final String ID = "RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_EVENT_V1";
    public static final String SEMANTICS =
            "TENANT_SCOPED_EXPLICIT_ACTIVE_POLICY_POINTER_APPEND_ONLY";
    public static final String CANONICAL_PAYLOAD_FORMAT =
            "RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_EVENT_CANONICAL_BINARY_V1";

    private final int activationRevision;
    private final ActivationState activationState;
    private final Integer policyRevision;
    private final String policySha256;
    private final String changedBy;
    private final String changeNote;
    private final Instant recordedAt;
    private final byte[] canonicalPayload;
    private final String eventSha256;

    private RbvmRiskMethodSelectionPolicyActivationEvent(
            int activationRevision,
            ActivationState activationState,
            Integer policyRevision,
            String policySha256,
            String changedBy,
            String changeNote,
            Instant recordedAt,
            String expectedEventSha256
    ) {
        if (activationRevision < 1) {
            throw new IllegalArgumentException("activationRevision must be positive");
        }
        this.activationRevision = activationRevision;
        this.activationState = Objects.requireNonNull(activationState, "activationState");
        if (activationState == ActivationState.ACTIVE) {
            if (policyRevision == null || policyRevision < 1) {
                throw new IllegalArgumentException("ACTIVE activation requires a positive policyRevision");
            }
            requireSha(policySha256, "policySha256");
        } else if (policyRevision != null || policySha256 != null) {
            throw new IllegalArgumentException("CLEARED activation must not carry a policy identity");
        }
        this.policyRevision = policyRevision;
        this.policySha256 = policySha256;
        this.changedBy = requireText(changedBy, "changedBy");
        this.changeNote = Objects.requireNonNull(changeNote, "changeNote");
        this.recordedAt = Objects.requireNonNull(recordedAt, "recordedAt");
        this.canonicalPayload = canonicalPayloadBytes();
        this.eventSha256 = sha256(canonicalPayload);
        if (expectedEventSha256 != null && !eventSha256.equals(expectedEventSha256)) {
            throw new IllegalArgumentException(
                    "eventSha256 does not match canonical activation event payload");
        }
    }

    public static RbvmRiskMethodSelectionPolicyActivationEvent activate(
            int activationRevision,
            RbvmRiskMethodSelectionPolicy policy,
            String changedBy,
            String changeNote,
            Instant recordedAt
    ) {
        Objects.requireNonNull(policy, "policy").requireCatalogBound();
        return new RbvmRiskMethodSelectionPolicyActivationEvent(
                activationRevision,
                ActivationState.ACTIVE,
                policy.revision(),
                policy.policySha256(),
                changedBy,
                changeNote,
                recordedAt,
                null
        );
    }

    public static RbvmRiskMethodSelectionPolicyActivationEvent clear(
            int activationRevision,
            String changedBy,
            String changeNote,
            Instant recordedAt
    ) {
        return new RbvmRiskMethodSelectionPolicyActivationEvent(
                activationRevision,
                ActivationState.CLEARED,
                null,
                null,
                changedBy,
                changeNote,
                recordedAt,
                null
        );
    }

    public static RbvmRiskMethodSelectionPolicyActivationEvent rehydrate(
            int activationRevision,
            ActivationState activationState,
            Integer policyRevision,
            String policySha256,
            String changedBy,
            String changeNote,
            Instant recordedAt,
            String eventSha256
    ) {
        requireSha(eventSha256, "eventSha256");
        return new RbvmRiskMethodSelectionPolicyActivationEvent(
                activationRevision,
                activationState,
                policyRevision,
                policySha256,
                changedBy,
                changeNote,
                recordedAt,
                eventSha256
        );
    }

    private byte[] canonicalPayloadBytes() {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                output.writeUTF(ID);
                output.writeUTF(SEMANTICS);
                output.writeInt(activationRevision);
                output.writeUTF(activationState.name());
                output.writeBoolean(policyRevision != null);
                if (policyRevision != null) {
                    output.writeInt(policyRevision);
                    output.writeUTF(policySha256);
                }
                output.writeUTF(changedBy);
                output.writeUTF(changeNote);
                output.writeLong(recordedAt.getEpochSecond());
                output.writeInt(recordedAt.getNano());
            }
            return buffer.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("Could not canonicalize in-memory activation event", impossible);
        }
    }

    public String contractId() { return ID; }
    public String semantics() { return SEMANTICS; }
    public int activationRevision() { return activationRevision; }
    public ActivationState activationState() { return activationState; }
    public Integer policyRevision() { return policyRevision; }
    public String policySha256() { return policySha256; }
    public String changedBy() { return changedBy; }
    public String changeNote() { return changeNote; }
    public Instant recordedAt() { return recordedAt; }
    public byte[] canonicalPayload() { return canonicalPayload.clone(); }
    public String eventSha256() { return eventSha256; }

    public boolean activatesPolicy() {
        return activationState == ActivationState.ACTIVE;
    }

    public enum ActivationState {
        ACTIVE,
        CLEARED
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
