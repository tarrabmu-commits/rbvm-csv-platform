package io.rbvm.postgres;

import io.rbvm.decision.RbvmDerivedRiskCanonicalResult;
import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;

import java.math.BigDecimal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

/** Immutable persisted canonical result for one exact derived risk methodology evaluation. */
public final class StoredDerivedRiskResult {
    private final UUID id;
    private final String inputSnapshotSha256;
    private final UUID findingId;
    private final String methodologyId;
    private final int methodologyVersion;
    private final String methodologySha256;
    private final RbvmDerivedRiskMethodology.ResultState resultState;
    private final String reasonCode;
    private final BigDecimal numericScore;
    private final String numericScale;
    private final String rating;
    private final String canonicalPayloadFormat;
    private final String resultSha256;
    private final byte[] canonicalPayload;
    private final Instant persistedAt;

    public StoredDerivedRiskResult(
            UUID id,
            String inputSnapshotSha256,
            UUID findingId,
            String methodologyId,
            int methodologyVersion,
            String methodologySha256,
            RbvmDerivedRiskMethodology.ResultState resultState,
            String reasonCode,
            BigDecimal numericScore,
            String numericScale,
            String rating,
            String canonicalPayloadFormat,
            String resultSha256,
            byte[] canonicalPayload,
            Instant persistedAt
    ) {
        this.id = Objects.requireNonNull(id, "id");
        this.inputSnapshotSha256 = requireSha(inputSnapshotSha256, "inputSnapshotSha256");
        this.findingId = Objects.requireNonNull(findingId, "findingId");
        this.methodologyId = requireText(methodologyId, "methodologyId");
        if (methodologyVersion < 1) {
            throw new IllegalArgumentException("methodologyVersion must be positive");
        }
        this.methodologyVersion = methodologyVersion;
        this.methodologySha256 = requireSha(methodologySha256, "methodologySha256");
        validateImplementedMethodology(this.methodologyId, this.methodologyVersion, this.methodologySha256);
        this.resultState = Objects.requireNonNull(resultState, "resultState");

        if (resultState == RbvmDerivedRiskMethodology.ResultState.COMPUTED) {
            if (reasonCode != null) {
                throw new IllegalArgumentException("COMPUTED result must not carry reasonCode");
            }
            this.reasonCode = null;
            this.numericScore = Objects.requireNonNull(numericScore, "numericScore");
            this.numericScale = requireText(numericScale, "numericScale");
            this.rating = rating == null ? null : requireText(rating, "rating");
        } else {
            this.reasonCode = requireText(reasonCode, "reasonCode");
            if (numericScore != null || numericScale != null || rating != null) {
                throw new IllegalArgumentException(
                        "Terminal derived risk result must not carry numeric score, scale, or rating"
                );
            }
            this.numericScore = null;
            this.numericScale = null;
            this.rating = null;
        }

        if (!RbvmDerivedRiskCanonicalResult.PAYLOAD_FORMAT.equals(canonicalPayloadFormat)) {
            throw new IllegalArgumentException(
                    "canonicalPayloadFormat must be RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1"
            );
        }
        this.canonicalPayloadFormat = canonicalPayloadFormat;
        this.resultSha256 = requireSha(resultSha256, "resultSha256");
        Objects.requireNonNull(canonicalPayload, "canonicalPayload");
        if (canonicalPayload.length == 0) {
            throw new IllegalArgumentException("canonicalPayload must not be empty");
        }
        this.canonicalPayload = canonicalPayload.clone();
        if (!sha256(this.canonicalPayload).equals(this.resultSha256)) {
            throw new IllegalArgumentException("resultSha256 does not match canonical payload bytes");
        }
        this.persistedAt = Objects.requireNonNull(persistedAt, "persistedAt");
    }

    public UUID id() { return id; }
    public String inputSnapshotSha256() { return inputSnapshotSha256; }
    public UUID findingId() { return findingId; }
    public String methodologyId() { return methodologyId; }
    public int methodologyVersion() { return methodologyVersion; }
    public String methodologySha256() { return methodologySha256; }
    public RbvmDerivedRiskMethodology.ResultState resultState() { return resultState; }
    public String reasonCode() { return reasonCode; }
    public BigDecimal numericScore() { return numericScore; }
    public String numericScale() { return numericScale; }
    public String rating() { return rating; }
    public String canonicalPayloadFormat() { return canonicalPayloadFormat; }
    public String resultSha256() { return resultSha256; }
    public byte[] canonicalPayload() { return canonicalPayload.clone(); }
    public Instant persistedAt() { return persistedAt; }

    /** Exact semantic/payload equality excluding database-generated row identity and persisted time. */
    public boolean samePersistedSemantics(StoredDerivedRiskResult other) {
        Objects.requireNonNull(other, "other");
        return inputSnapshotSha256.equals(other.inputSnapshotSha256)
                && findingId.equals(other.findingId)
                && methodologyId.equals(other.methodologyId)
                && methodologyVersion == other.methodologyVersion
                && methodologySha256.equals(other.methodologySha256)
                && resultState == other.resultState
                && Objects.equals(reasonCode, other.reasonCode)
                && Objects.equals(numericScore, other.numericScore)
                && Objects.equals(numericScale, other.numericScale)
                && Objects.equals(rating, other.rating)
                && canonicalPayloadFormat.equals(other.canonicalPayloadFormat)
                && resultSha256.equals(other.resultSha256)
                && Arrays.equals(canonicalPayload, other.canonicalPayload);
    }

    private static void validateImplementedMethodology(String id, int version, String sha) {
        RbvmDerivedRiskMethodology methodology = RbvmDerivedRiskMethodologyCatalog.find(id)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Persisted derived risk methodology is not implemented: " + id
                ));
        RbvmDerivedRiskMethodology.Definition definition = methodology.definition();
        if (definition.version() != version || !definition.methodologySha256().equals(sha)) {
            throw new IllegalArgumentException(
                    "Persisted derived risk methodology identity does not match implementation"
            );
        }
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
