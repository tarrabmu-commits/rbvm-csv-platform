package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmFormulaV1.FactorContribution;
import io.rbvm.decision.RbvmFormulaV1.FormulaResult;
import io.rbvm.decision.RbvmFormulaV1.ResultState;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityEvidenceValue;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Deterministic canonical explanation for one accepted RBVM Formula V1 evaluation.
 *
 * <p>The explanation is derived only from one exact resolved Decision Input V3 and the exact
 * deterministic Formula V1 result for that input. It performs no evidence selection, current-state
 * lookup, persistence, priority mapping, treatment decision, or SLA calculation.</p>
 */
public final class RbvmFormulaV1Explanation {
    public static final String PAYLOAD_FORMAT =
            "RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1";

    private final ResultState resultState;
    private final String formulaId;
    private final int formulaVersion;
    private final String formulaSha256;
    private final String inputContractId;
    private final String inputSnapshotSha256;
    private final UUID findingId;
    private final Instant evaluatedAt;
    private final int methodologyRevision;
    private final String methodologyPolicySha256;
    private final List<DimensionExplanation> dimensions;
    private final List<String> reasonCodes;
    private final BigDecimal finalRiskResult;
    private final byte[] canonicalPayload;
    private final String canonicalSha256;

    private RbvmFormulaV1Explanation(
            ResultState resultState,
            String formulaId,
            int formulaVersion,
            String formulaSha256,
            String inputContractId,
            String inputSnapshotSha256,
            UUID findingId,
            Instant evaluatedAt,
            int methodologyRevision,
            String methodologyPolicySha256,
            List<DimensionExplanation> dimensions,
            List<String> reasonCodes,
            BigDecimal finalRiskResult
    ) {
        this.resultState = Objects.requireNonNull(resultState, "resultState");
        this.formulaId = requireText(formulaId, "formulaId");
        if (formulaVersion < 1) {
            throw new IllegalArgumentException("formulaVersion must be positive");
        }
        this.formulaVersion = formulaVersion;
        this.formulaSha256 = requireSha(formulaSha256, "formulaSha256");
        this.inputContractId = requireText(inputContractId, "inputContractId");
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
        this.dimensions = validateDimensions(dimensions);
        this.reasonCodes = validateReasonCodes(resultState, reasonCodes);
        this.finalRiskResult = validateFinalResult(resultState, finalRiskResult);
        this.canonicalPayload = canonicalPayloadInternal();
        this.canonicalSha256 = sha256(canonicalPayload);
    }

    /** Builds the canonical explanation only for the exact Formula result produced by this input. */
    public static RbvmFormulaV1Explanation from(
            RbvmResolvedDecisionInput input,
            FormulaResult result
    ) {
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(result, "result");
        if (!input.snapshot().isV3()) {
            throw new IllegalArgumentException(
                    "Formula V1 explanation accepts only RBVM_DECISION_INPUT_SNAPSHOT_V3"
            );
        }
        FormulaResult expected = RbvmFormulaV1.evaluate(input);
        if (!expected.equals(result)) {
            throw new IllegalArgumentException(
                    "Formula explanation result must exactly match deterministic Formula V1 evaluation"
            );
        }

        RbvmDecisionInputSnapshot snapshot = input.snapshot();
        Map<EvidenceDimension, FactorContribution> contributions = contributions(result);
        List<DimensionExplanation> dimensionEntries = new ArrayList<>();
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            DimensionInput dimensionInput = snapshot.dimensions().get(dimension);
            FactorContribution contribution = contributions.get(dimension);
            String normalizedValue = null;
            String appliedIdentifier = null;
            BigDecimal weightedContribution = null;

            if (result.state() == ResultState.COMPUTED && contribution != null) {
                normalizedValue = canonicalDecimalText(contribution.normalizedValue());
                appliedIdentifier = contribution.factorId();
                weightedContribution = contribution.weightedContribution();
            } else if (dimension == EvidenceDimension.APPLICABILITY
                    && dimensionInput.state() == DimensionState.PRESENT) {
                normalizedValue = applicabilityStatus(input);
            }

            dimensionEntries.add(new DimensionExplanation(
                    dimension,
                    dimensionInput.state(),
                    dimensionInput.evidenceReferences(),
                    normalizedValue,
                    appliedIdentifier,
                    weightedContribution
            ));
        }

        List<String> reasonCodes = result.reasonCode() == null
                ? List.of()
                : List.of(result.reasonCode());

        return new RbvmFormulaV1Explanation(
                result.state(),
                result.formulaId(),
                result.formulaVersion(),
                result.formulaSha256(),
                result.inputContractId(),
                result.inputSnapshotSha256(),
                result.findingId(),
                snapshot.evaluatedAt(),
                snapshot.methodologyRevision(),
                snapshot.methodologyPolicySha256(),
                dimensionEntries,
                reasonCodes,
                result.relativeRiskIndex()
        );
    }

    public ResultState resultState() {
        return resultState;
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

    public String inputContractId() {
        return inputContractId;
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

    public List<DimensionExplanation> dimensions() {
        return dimensions;
    }

    public List<String> reasonCodes() {
        return reasonCodes;
    }

    public BigDecimal finalRiskResult() {
        return finalRiskResult;
    }

    public byte[] canonicalPayload() {
        return canonicalPayload.clone();
    }

    public String canonicalSha256() {
        return canonicalSha256;
    }

    public record DimensionExplanation(
            EvidenceDimension dimension,
            DimensionState state,
            List<EvidenceReference> evidenceReferences,
            String normalizedValue,
            String appliedFactorOrTransformId,
            BigDecimal weightedContribution
    ) {
        public DimensionExplanation {
            dimension = Objects.requireNonNull(dimension, "dimension");
            state = Objects.requireNonNull(state, "state");
            Objects.requireNonNull(evidenceReferences, "evidenceReferences");
            List<EvidenceReference> normalizedReferences = new ArrayList<>(evidenceReferences.size());
            for (EvidenceReference reference : evidenceReferences) {
                Objects.requireNonNull(reference, "evidenceReference");
                if (reference.dimension() != dimension) {
                    throw new IllegalArgumentException(
                            "Explanation evidence reference dimension must match dimension entry"
                    );
                }
                normalizedReferences.add(reference);
            }
            evidenceReferences = List.copyOf(normalizedReferences);
            normalizedValue = normalizeNullableText(normalizedValue, "normalizedValue");
            appliedFactorOrTransformId = normalizeNullableText(
                    appliedFactorOrTransformId,
                    "appliedFactorOrTransformId"
            );
            if ((appliedFactorOrTransformId == null) != (weightedContribution == null)) {
                throw new IllegalArgumentException(
                        "Formula contribution identifier and numeric contribution must appear together"
                );
            }
            if (weightedContribution != null) {
                if (weightedContribution.compareTo(BigDecimal.ZERO) < 0
                        || weightedContribution.compareTo(BigDecimal.ONE) > 0) {
                    throw new IllegalArgumentException(
                            "weightedContribution must be between 0 and 1"
                    );
                }
                weightedContribution = canonicalDecimal(weightedContribution);
            }
        }
    }

    private byte[] canonicalPayloadInternal() {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                writeString(output, PAYLOAD_FORMAT);
                writeString(output, resultState.name());
                writeString(output, formulaId);
                output.writeInt(formulaVersion);
                writeString(output, formulaSha256);
                writeString(output, inputContractId);
                writeString(output, inputSnapshotSha256);
                writeString(output, findingId.toString());
                writeString(output, evaluatedAt.toString());
                output.writeInt(methodologyRevision);
                writeString(output, methodologyPolicySha256);

                output.writeInt(dimensions.size());
                for (DimensionExplanation dimension : dimensions) {
                    writeDimension(output, dimension);
                }

                output.writeInt(reasonCodes.size());
                for (String reasonCode : reasonCodes) {
                    writeString(output, reasonCode);
                }
                writeNullableString(
                        output,
                        finalRiskResult == null ? null : canonicalDecimalText(finalRiskResult)
                );
            }
            return buffer.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException("Could not canonicalize Formula explanation", exception);
        }
    }

    private static void writeDimension(
            DataOutputStream output,
            DimensionExplanation dimension
    ) throws IOException {
        writeString(output, dimension.dimension().name());
        writeString(output, dimension.state().name());
        output.writeInt(dimension.evidenceReferences().size());
        for (EvidenceReference reference : dimension.evidenceReferences()) {
            writeString(output, reference.nativeEvidenceKind().name());
            writeString(output, reference.evidenceId().toString());
            writeString(output, reference.evidenceSha256());
            writeString(output, reference.evidenceSource());
            writeString(output, reference.observedAt().toString());
            writeBinding(output, reference.bindingReference());
        }
        writeNullableString(output, dimension.normalizedValue());
        writeNullableString(output, dimension.appliedFactorOrTransformId());
        writeNullableString(
                output,
                dimension.weightedContribution() == null
                        ? null
                        : canonicalDecimalText(dimension.weightedContribution())
        );
    }

    private static void writeBinding(
            DataOutputStream output,
            BindingReference binding
    ) throws IOException {
        if (binding == null) {
            output.writeByte(0);
            return;
        }
        output.writeByte(1);
        writeString(output, binding.bindingKind().name());
        writeString(output, binding.bindingId().toString());
        writeString(output, binding.bindingSha256());
        writeString(output, binding.bindingSource());
        writeString(output, binding.recordedAt().toString());
    }

    private static void writeNullableString(DataOutputStream output, String value)
            throws IOException {
        if (value == null) {
            output.writeByte(0);
        } else {
            output.writeByte(1);
            writeString(output, value);
        }
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] bytes = requireText(value, "canonical string").getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static List<DimensionExplanation> validateDimensions(
            List<DimensionExplanation> input
    ) {
        Objects.requireNonNull(input, "dimensions");
        if (input.size() != EvidenceDimension.values().length) {
            throw new IllegalArgumentException(
                    "Formula explanation must contain exactly the seven Decision Input dimensions"
            );
        }
        List<DimensionExplanation> normalized = new ArrayList<>(input.size());
        for (int index = 0; index < EvidenceDimension.values().length; index++) {
            DimensionExplanation entry = Objects.requireNonNull(
                    input.get(index),
                    "dimension explanation"
            );
            if (entry.dimension() != EvidenceDimension.values()[index]) {
                throw new IllegalArgumentException(
                        "Formula explanation dimensions must follow fixed EvidenceDimension order"
                );
            }
            normalized.add(entry);
        }
        return List.copyOf(normalized);
    }

    private static List<String> validateReasonCodes(
            ResultState state,
            List<String> input
    ) {
        Objects.requireNonNull(input, "reasonCodes");
        List<String> normalized = input.stream()
                .map(value -> requireText(value, "reasonCode"))
                .toList();
        if (state == ResultState.COMPUTED && !normalized.isEmpty()) {
            throw new IllegalArgumentException("COMPUTED explanation must not carry reason codes");
        }
        if (state != ResultState.COMPUTED && normalized.isEmpty()) {
            throw new IllegalArgumentException("Terminal explanation requires a reason code");
        }
        return normalized;
    }

    private static BigDecimal validateFinalResult(
            ResultState state,
            BigDecimal value
    ) {
        if (state == ResultState.COMPUTED) {
            Objects.requireNonNull(value, "finalRiskResult");
            if (value.scale() != 2
                    || value.compareTo(BigDecimal.ZERO) < 0
                    || value.compareTo(new BigDecimal("100")) > 0) {
                throw new IllegalArgumentException(
                        "COMPUTED explanation result must be 0.00..100.00 with scale 2"
                );
            }
            return value;
        }
        if (value != null) {
            throw new IllegalArgumentException(
                    "NOT_APPLICABLE/NON_COMPUTABLE explanation must not carry a numeric result"
            );
        }
        return null;
    }

    private static Map<EvidenceDimension, FactorContribution> contributions(
            FormulaResult result
    ) {
        EnumMap<EvidenceDimension, FactorContribution> byDimension =
                new EnumMap<>(EvidenceDimension.class);
        for (FactorContribution contribution : result.factorContributions()) {
            FactorContribution previous = byDimension.put(
                    contribution.dimension(),
                    contribution
            );
            if (previous != null) {
                throw new IllegalArgumentException(
                        "Formula result contains duplicate factor contribution dimension"
                );
            }
        }
        return Map.copyOf(byDimension);
    }

    private static String applicabilityStatus(RbvmResolvedDecisionInput input) {
        List<RbvmResolvedDecisionInput.ResolvedEvidence> values =
                input.evidence(EvidenceDimension.APPLICABILITY);
        if (values.size() != 1 || !(values.get(0) instanceof ApplicabilityEvidenceValue value)) {
            return null;
        }
        return value.status().name();
    }

    private static BigDecimal canonicalDecimal(BigDecimal value) {
        if (value.compareTo(BigDecimal.ZERO) == 0) {
            return BigDecimal.ZERO;
        }
        return value.stripTrailingZeros();
    }

    private static String canonicalDecimalText(BigDecimal value) {
        return canonicalDecimal(Objects.requireNonNull(value, "decimal")).toPlainString();
    }

    private static String normalizeNullableText(String value, String field) {
        return value == null ? null : requireText(value, field);
    }

    private static String requireText(String value, String field) {
        if (value == null || value.trim().isEmpty() || value.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " must be non-empty text");
        }
        return value.trim();
    }

    private static String requireSha(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256 hex");
        }
        return value;
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }
}
