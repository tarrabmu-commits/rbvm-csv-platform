package io.rbvm.postgres;

import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmFormulaV1.ResultState;
import io.rbvm.decision.RbvmFormulaV1Explanation;

import java.math.BigDecimal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Immutable persisted Formula V1 result plus exact canonical explanation bytes. */
public final class StoredFormulaResult {
    private final UUID id;
    private final String inputSnapshotSha256;
    private final UUID findingId;
    private final Instant evaluatedAt;
    private final int methodologyRevision;
    private final String methodologyPolicySha256;
    private final String formulaId;
    private final int formulaVersion;
    private final String formulaSha256;
    private final ResultState resultState;
    private final List<String> reasonCodes;
    private final BigDecimal relativeRiskIndex;
    private final String explanationPayloadFormat;
    private final String explanationSha256;
    private final byte[] explanationPayload;
    private final Instant persistedAt;

    public StoredFormulaResult(
            UUID id,
            String inputSnapshotSha256,
            UUID findingId,
            Instant evaluatedAt,
            int methodologyRevision,
            String methodologyPolicySha256,
            String formulaId,
            int formulaVersion,
            String formulaSha256,
            ResultState resultState,
            List<String> reasonCodes,
            BigDecimal relativeRiskIndex,
            String explanationPayloadFormat,
            String explanationSha256,
            byte[] explanationPayload,
            Instant persistedAt
    ) {
        this.id = Objects.requireNonNull(id, "id");
        this.inputSnapshotSha256 = requireSha(inputSnapshotSha256, "inputSnapshotSha256");
        this.findingId = Objects.requireNonNull(findingId, "findingId");
        this.evaluatedAt = Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        if (methodologyRevision < 1) {
            throw new IllegalArgumentException("methodologyRevision must be positive");
        }
        this.methodologyRevision = methodologyRevision;
        this.methodologyPolicySha256 = requireSha(
                methodologyPolicySha256,
                "methodologyPolicySha256"
        );
        if (!RbvmFormulaV1.FORMULA_ID.equals(formulaId)) {
            throw new IllegalArgumentException("formulaId must be RBVM_FORMULA_V1");
        }
        this.formulaId = formulaId;
        if (formulaVersion != RbvmFormulaV1.FORMULA_VERSION) {
            throw new IllegalArgumentException("formulaVersion must be Formula V1");
        }
        this.formulaVersion = formulaVersion;
        this.formulaSha256 = requireSha(formulaSha256, "formulaSha256");
        if (!RbvmFormulaV1.FORMULA_SHA256.equals(this.formulaSha256)) {
            throw new IllegalArgumentException("formulaSha256 must match accepted Formula V1");
        }
        this.resultState = Objects.requireNonNull(resultState, "resultState");
        Objects.requireNonNull(reasonCodes, "reasonCodes");
        List<String> normalizedReasons = new ArrayList<>(reasonCodes.size());
        for (String reason : reasonCodes) {
            normalizedReasons.add(requireText(reason, "reasonCode"));
        }
        this.reasonCodes = List.copyOf(normalizedReasons);
        this.relativeRiskIndex = validateResultShape(resultState, this.reasonCodes, relativeRiskIndex);
        if (!RbvmFormulaV1Explanation.PAYLOAD_FORMAT.equals(explanationPayloadFormat)) {
            throw new IllegalArgumentException(
                    "explanationPayloadFormat must be RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1"
            );
        }
        this.explanationPayloadFormat = explanationPayloadFormat;
        this.explanationSha256 = requireSha(explanationSha256, "explanationSha256");
        Objects.requireNonNull(explanationPayload, "explanationPayload");
        if (explanationPayload.length == 0) {
            throw new IllegalArgumentException("explanationPayload must not be empty");
        }
        this.explanationPayload = explanationPayload.clone();
        String actual = sha256(this.explanationPayload);
        if (!actual.equals(this.explanationSha256)) {
            throw new IllegalArgumentException(
                    "explanationSha256 does not match persisted canonical explanation bytes"
            );
        }
        this.persistedAt = Objects.requireNonNull(persistedAt, "persistedAt");
    }

    public UUID id() {
        return id;
    }

    public String inputSnapshotSha256() {
        return inputSnapshotSha256;
    }

    public UUID findingId() {
        return findingId;
    }

    public Instant evaluatedAt() {
        return evaluatedAt;
    }

    public int methodologyRevision() {
        return methodologyRevision;
    }

    public String methodologyPolicySha256() {
        return methodologyPolicySha256;
    }

    public String formulaId() {
        return formulaId;
    }

    public int formulaVersion() {
        return formulaVersion;
    }

    public String formulaSha256() {
        return formulaSha256;
    }

    public ResultState resultState() {
        return resultState;
    }

    public List<String> reasonCodes() {
        return reasonCodes;
    }

    public BigDecimal relativeRiskIndex() {
        return relativeRiskIndex;
    }

    public String explanationPayloadFormat() {
        return explanationPayloadFormat;
    }

    public String explanationSha256() {
        return explanationSha256;
    }

    public byte[] explanationPayload() {
        return explanationPayload.clone();
    }

    public Instant persistedAt() {
        return persistedAt;
    }

    /** Exact semantic/payload equality excluding database-generated row identity and persisted time. */
    public boolean samePersistedSemantics(StoredFormulaResult other) {
        Objects.requireNonNull(other, "other");
        return inputSnapshotSha256.equals(other.inputSnapshotSha256)
                && findingId.equals(other.findingId)
                && evaluatedAt.equals(other.evaluatedAt)
                && methodologyRevision == other.methodologyRevision
                && methodologyPolicySha256.equals(other.methodologyPolicySha256)
                && formulaId.equals(other.formulaId)
                && formulaVersion == other.formulaVersion
                && formulaSha256.equals(other.formulaSha256)
                && resultState == other.resultState
                && reasonCodes.equals(other.reasonCodes)
                && Objects.equals(relativeRiskIndex, other.relativeRiskIndex)
                && explanationPayloadFormat.equals(other.explanationPayloadFormat)
                && explanationSha256.equals(other.explanationSha256)
                && Arrays.equals(explanationPayload, other.explanationPayload);
    }

    private static BigDecimal validateResultShape(
            ResultState state,
            List<String> reasonCodes,
            BigDecimal value
    ) {
        if (state == ResultState.COMPUTED) {
            if (!reasonCodes.isEmpty()) {
                throw new IllegalArgumentException("COMPUTED result must not carry reason codes");
            }
            Objects.requireNonNull(value, "relativeRiskIndex");
            if (value.scale() != 2
                    || value.compareTo(BigDecimal.ZERO) < 0
                    || value.compareTo(new BigDecimal("100")) > 0) {
                throw new IllegalArgumentException(
                        "COMPUTED relativeRiskIndex must be 0.00..100.00 with scale 2"
                );
            }
            return value;
        }
        if (reasonCodes.isEmpty()) {
            throw new IllegalArgumentException("Terminal Formula result requires a reason code");
        }
        if (value != null) {
            throw new IllegalArgumentException(
                    "NOT_APPLICABLE/NON_COMPUTABLE result must not carry a numeric risk index"
            );
        }
        return null;
    }

    private static String requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
        return value;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank() || value.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " must be non-empty text");
        }
        return value.trim();
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }
}
