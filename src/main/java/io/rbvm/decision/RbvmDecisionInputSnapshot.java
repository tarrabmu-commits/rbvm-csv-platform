package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Immutable, policy-bound evidence-reference snapshot for one canonical Finding_ID.
 *
 * <p>The snapshot records evidence eligibility state only. It contains no evidence values, risk
 * score, priority, SLA, formula result, weights, or Case aggregation.</p>
 */
public record RbvmDecisionInputSnapshot(
        String contractId,
        String snapshotSha256,
        UUID findingId,
        int methodologyRevision,
        String methodologyPolicySha256,
        Instant evaluatedAt,
        Map<EvidenceDimension, DimensionInput> dimensions
) {
    public static final String ID = "RBVM_DECISION_INPUT_SNAPSHOT_V1";
    public static final String SEMANTICS =
            "FINDING_SCOPED_POLICY_BOUND_EVIDENCE_REFERENCE_SNAPSHOT";
    public static final String CANONICAL_PAYLOAD_FORMAT =
            "RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V1";

    public RbvmDecisionInputSnapshot {
        if (!ID.equals(contractId)) {
            throw new IllegalArgumentException("contractId must be " + ID);
        }
        findingId = Objects.requireNonNull(findingId, "findingId");
        if (methodologyRevision < 1) {
            throw new IllegalArgumentException("methodologyRevision must be positive");
        }
        methodologyPolicySha256 = requireSha(methodologyPolicySha256, "methodologyPolicySha256");
        evaluatedAt = Objects.requireNonNull(evaluatedAt, "evaluatedAt");

        EnumMap<EvidenceDimension, DimensionInput> normalized = normalizeDimensions(
                dimensions,
                evaluatedAt
        );
        dimensions = Collections.unmodifiableMap(normalized);
        snapshotSha256 = requireSha(snapshotSha256, "snapshotSha256");
        String expected = canonicalSha256(
                contractId,
                findingId,
                methodologyRevision,
                methodologyPolicySha256,
                evaluatedAt,
                normalized
        );
        if (!snapshotSha256.equals(expected)) {
            throw new IllegalArgumentException(
                    "snapshotSha256 does not match the canonical decision-input payload");
        }
    }

    public static RbvmDecisionInputSnapshot create(
            UUID findingId,
            int methodologyRevision,
            String methodologyPolicySha256,
            Instant evaluatedAt,
            Map<EvidenceDimension, DimensionInput> dimensions
    ) {
        EnumMap<EvidenceDimension, DimensionInput> normalized = normalizeDimensions(
                dimensions,
                Objects.requireNonNull(evaluatedAt, "evaluatedAt")
        );
        String sha = canonicalSha256(
                ID,
                Objects.requireNonNull(findingId, "findingId"),
                methodologyRevision,
                requireSha(methodologyPolicySha256, "methodologyPolicySha256"),
                evaluatedAt,
                normalized
        );
        return new RbvmDecisionInputSnapshot(
                ID,
                sha,
                findingId,
                methodologyRevision,
                methodologyPolicySha256,
                evaluatedAt,
                normalized
        );
    }

    public String semantics() {
        return SEMANTICS;
    }

    public byte[] canonicalPayload() {
        return canonicalPayload(
                contractId,
                findingId,
                methodologyRevision,
                methodologyPolicySha256,
                evaluatedAt,
                dimensions
        );
    }

    public enum DimensionState {
        PRESENT,
        MISSING,
        AMBIGUOUS,
        STALE
    }

    public record DimensionInput(
            EvidenceDimension dimension,
            DimensionState state,
            List<EvidenceReference> evidenceReferences
    ) {
        public DimensionInput {
            dimension = Objects.requireNonNull(dimension, "dimension");
            state = Objects.requireNonNull(state, "state");
            Objects.requireNonNull(evidenceReferences, "evidenceReferences");

            List<EvidenceReference> normalized = new ArrayList<>(evidenceReferences.size());
            Set<UUID> evidenceIds = new HashSet<>();
            for (EvidenceReference reference : evidenceReferences) {
                Objects.requireNonNull(reference, "evidenceReference");
                if (reference.dimension() != dimension) {
                    throw new IllegalArgumentException(
                            "Evidence reference dimension must match DimensionInput dimension");
                }
                if (!evidenceIds.add(reference.evidenceId())) {
                    throw new IllegalArgumentException(
                            "DimensionInput must not repeat an evidence UUID");
                }
                normalized.add(reference);
            }
            normalized.sort(Comparator.comparing(EvidenceReference::evidenceId));
            evidenceReferences = List.copyOf(normalized);

            switch (state) {
                case MISSING -> {
                    if (!evidenceReferences.isEmpty()) {
                        throw new IllegalArgumentException(
                                "MISSING dimension must not reference fabricated evidence");
                    }
                }
                case PRESENT, STALE -> {
                    if (evidenceReferences.isEmpty()) {
                        throw new IllegalArgumentException(
                                state + " dimension requires at least one evidence reference");
                    }
                }
                case AMBIGUOUS -> {
                    if (evidenceReferences.size() < 2) {
                        throw new IllegalArgumentException(
                                "AMBIGUOUS dimension requires at least two evidence references");
                    }
                }
            }
        }
    }

    /** Immutable pointer to one native evidence row; values remain in the native evidence table. */
    public record EvidenceReference(
            EvidenceDimension dimension,
            UUID evidenceId,
            String evidenceSha256,
            String evidenceSource,
            Instant observedAt
    ) {
        public EvidenceReference {
            dimension = Objects.requireNonNull(dimension, "dimension");
            evidenceId = Objects.requireNonNull(evidenceId, "evidenceId");
            evidenceSha256 = requireSha(evidenceSha256, "evidenceSha256");
            if (evidenceSource == null
                    || evidenceSource.trim().isEmpty()
                    || evidenceSource.trim().length() > 256
                    || evidenceSource.indexOf('\u0000') >= 0) {
                throw new IllegalArgumentException("evidenceSource is invalid");
            }
            evidenceSource = evidenceSource.trim();
            observedAt = Objects.requireNonNull(observedAt, "observedAt");
        }
    }

    private static EnumMap<EvidenceDimension, DimensionInput> normalizeDimensions(
            Map<EvidenceDimension, DimensionInput> dimensions,
            Instant evaluatedAt
    ) {
        Objects.requireNonNull(dimensions, "dimensions");
        EnumMap<EvidenceDimension, DimensionInput> normalized =
                new EnumMap<>(EvidenceDimension.class);
        normalized.putAll(dimensions);
        if (!normalized.keySet().equals(Set.of(EvidenceDimension.values()))) {
            throw new IllegalArgumentException(
                    "Decision input snapshot must classify every evidence dimension");
        }
        for (Map.Entry<EvidenceDimension, DimensionInput> entry : normalized.entrySet()) {
            DimensionInput input = Objects.requireNonNull(entry.getValue(), "dimensionInput");
            if (input.dimension() != entry.getKey()) {
                throw new IllegalArgumentException(
                        "Decision input map key must match DimensionInput dimension");
            }
            for (EvidenceReference reference : input.evidenceReferences()) {
                if (reference.observedAt().isAfter(evaluatedAt)) {
                    throw new IllegalArgumentException(
                            "Decision input must not reference evidence observed after evaluatedAt");
                }
            }
        }
        return normalized;
    }

    private static String canonicalSha256(
            String contractId,
            UUID findingId,
            int methodologyRevision,
            String methodologyPolicySha256,
            Instant evaluatedAt,
            Map<EvidenceDimension, DimensionInput> dimensions
    ) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                    canonicalPayload(
                            contractId,
                            findingId,
                            methodologyRevision,
                            methodologyPolicySha256,
                            evaluatedAt,
                            dimensions
                    )
            ));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    private static byte[] canonicalPayload(
            String contractId,
            UUID findingId,
            int methodologyRevision,
            String methodologyPolicySha256,
            Instant evaluatedAt,
            Map<EvidenceDimension, DimensionInput> dimensions
    ) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                writeString(output, CANONICAL_PAYLOAD_FORMAT);
                writeString(output, contractId);
                writeString(output, SEMANTICS);
                output.writeLong(findingId.getMostSignificantBits());
                output.writeLong(findingId.getLeastSignificantBits());
                output.writeInt(methodologyRevision);
                writeString(output, methodologyPolicySha256);
                output.writeLong(evaluatedAt.getEpochSecond());
                output.writeInt(evaluatedAt.getNano());
                for (EvidenceDimension dimension : EvidenceDimension.values()) {
                    DimensionInput input = Objects.requireNonNull(dimensions.get(dimension));
                    writeString(output, dimension.name());
                    writeString(output, input.state().name());
                    output.writeInt(input.evidenceReferences().size());
                    for (EvidenceReference reference : input.evidenceReferences()) {
                        output.writeLong(reference.evidenceId().getMostSignificantBits());
                        output.writeLong(reference.evidenceId().getLeastSignificantBits());
                        writeString(output, reference.evidenceSha256());
                        writeString(output, reference.evidenceSource());
                        output.writeLong(reference.observedAt().getEpochSecond());
                        output.writeInt(reference.observedAt().getNano());
                    }
                }
            }
            return buffer.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException("Unexpected in-memory snapshot canonicalization failure", exception);
        }
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static String requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
        return value;
    }
}
