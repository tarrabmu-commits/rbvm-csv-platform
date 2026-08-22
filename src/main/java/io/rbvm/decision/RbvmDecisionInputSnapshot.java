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
 * <p>V1 references are dimension-addressed. V2 adds an explicit native-evidence kind and, for
 * managed-asset context, the exact scanner-to-managed-asset link event that authorized the join.
 * V3 additionally binds Network Reachability and Business/Mission Impact references to the exact
 * customer-confirmed Finding-specific association events that authorized those joins. No version
 * contains a decision formula or a source winner.</p>
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
    public static final String V1_ID = "RBVM_DECISION_INPUT_SNAPSHOT_V1";
    public static final String V2_ID = "RBVM_DECISION_INPUT_SNAPSHOT_V2";
    public static final String V3_ID = "RBVM_DECISION_INPUT_SNAPSHOT_V3";
    /** Backward-compatible alias for the historical V1 contract. */
    public static final String ID = V1_ID;

    public static final String V1_SEMANTICS =
            "FINDING_SCOPED_POLICY_BOUND_EVIDENCE_REFERENCE_SNAPSHOT";
    public static final String V2_SEMANTICS =
            "FINDING_SCOPED_POLICY_BOUND_TYPED_EVIDENCE_REFERENCE_SNAPSHOT";
    public static final String V3_SEMANTICS =
            "FINDING_SCOPED_POLICY_BOUND_TYPED_ASSOCIATION_PROVENANCE_SNAPSHOT";
    /** Backward-compatible alias for the historical V1 semantics. */
    public static final String SEMANTICS = V1_SEMANTICS;

    public static final String V1_CANONICAL_PAYLOAD_FORMAT =
            "RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V1";
    public static final String V2_CANONICAL_PAYLOAD_FORMAT =
            "RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V2";
    public static final String V3_CANONICAL_PAYLOAD_FORMAT =
            "RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V3";
    /** Backward-compatible alias for the historical V1 payload format. */
    public static final String CANONICAL_PAYLOAD_FORMAT = V1_CANONICAL_PAYLOAD_FORMAT;

    public RbvmDecisionInputSnapshot {
        requireContract(contractId);
        findingId = Objects.requireNonNull(findingId, "findingId");
        if (methodologyRevision < 1) {
            throw new IllegalArgumentException("methodologyRevision must be positive");
        }
        methodologyPolicySha256 = requireSha(methodologyPolicySha256, "methodologyPolicySha256");
        evaluatedAt = Objects.requireNonNull(evaluatedAt, "evaluatedAt");

        EnumMap<EvidenceDimension, DimensionInput> normalized =
                normalizeDimensions(dimensions, evaluatedAt, contractId);
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
        return createForContract(
                V1_ID,
                findingId,
                methodologyRevision,
                methodologyPolicySha256,
                evaluatedAt,
                dimensions
        );
    }

    public static RbvmDecisionInputSnapshot createV2(
            UUID findingId,
            int methodologyRevision,
            String methodologyPolicySha256,
            Instant evaluatedAt,
            Map<EvidenceDimension, DimensionInput> dimensions
    ) {
        return createForContract(
                V2_ID,
                findingId,
                methodologyRevision,
                methodologyPolicySha256,
                evaluatedAt,
                dimensions
        );
    }

    public static RbvmDecisionInputSnapshot createV3(
            UUID findingId,
            int methodologyRevision,
            String methodologyPolicySha256,
            Instant evaluatedAt,
            Map<EvidenceDimension, DimensionInput> dimensions
    ) {
        return createForContract(
                V3_ID,
                findingId,
                methodologyRevision,
                methodologyPolicySha256,
                evaluatedAt,
                dimensions
        );
    }

    private static RbvmDecisionInputSnapshot createForContract(
            String contractId,
            UUID findingId,
            int methodologyRevision,
            String methodologyPolicySha256,
            Instant evaluatedAt,
            Map<EvidenceDimension, DimensionInput> dimensions
    ) {
        requireContract(contractId);
        Objects.requireNonNull(findingId, "findingId");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        EnumMap<EvidenceDimension, DimensionInput> normalized =
                normalizeDimensions(dimensions, evaluatedAt, contractId);
        String normalizedPolicySha = requireSha(
                methodologyPolicySha256,
                "methodologyPolicySha256"
        );
        String sha = canonicalSha256(
                contractId,
                findingId,
                methodologyRevision,
                normalizedPolicySha,
                evaluatedAt,
                normalized
        );
        return new RbvmDecisionInputSnapshot(
                contractId,
                sha,
                findingId,
                methodologyRevision,
                normalizedPolicySha,
                evaluatedAt,
                normalized
        );
    }

    public boolean isV2() {
        return V2_ID.equals(contractId);
    }

    public boolean isV3() {
        return V3_ID.equals(contractId);
    }

    public String semantics() {
        return semanticsFor(contractId);
    }

    public String canonicalPayloadFormat() {
        return canonicalPayloadFormatFor(contractId);
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

    public enum NativeEvidenceKind {
        APPLICABILITY_ASSESSMENT(EvidenceDimension.APPLICABILITY),
        CVSS_V31_BASE_EVIDENCE(EvidenceDimension.TECHNICAL_SEVERITY),
        CISA_KEV_EVIDENCE(EvidenceDimension.KNOWN_EXPLOITATION),
        EPSS_EVIDENCE(EvidenceDimension.EXPLOITATION_PROBABILITY),
        ASSET_CONTEXT_EVIDENCE(EvidenceDimension.ASSET_CONTEXT),
        MANAGED_ASSET_REVISION(EvidenceDimension.ASSET_CONTEXT),
        NETWORK_REACHABILITY_EVIDENCE(EvidenceDimension.NETWORK_REACHABILITY),
        BUSINESS_IMPACT_EVIDENCE(EvidenceDimension.BUSINESS_MISSION_IMPACT);

        private final EvidenceDimension dimension;

        NativeEvidenceKind(EvidenceDimension dimension) {
            this.dimension = dimension;
        }

        public boolean supports(EvidenceDimension candidateDimension) {
            return dimension == candidateDimension;
        }

        public static NativeEvidenceKind defaultFor(EvidenceDimension dimension) {
            return switch (Objects.requireNonNull(dimension, "dimension")) {
                case APPLICABILITY -> APPLICABILITY_ASSESSMENT;
                case TECHNICAL_SEVERITY -> CVSS_V31_BASE_EVIDENCE;
                case KNOWN_EXPLOITATION -> CISA_KEV_EVIDENCE;
                case EXPLOITATION_PROBABILITY -> EPSS_EVIDENCE;
                case ASSET_CONTEXT -> ASSET_CONTEXT_EVIDENCE;
                case NETWORK_REACHABILITY -> NETWORK_REACHABILITY_EVIDENCE;
                case BUSINESS_MISSION_IMPACT -> BUSINESS_IMPACT_EVIDENCE;
            };
        }
    }

    public enum BindingKind {
        SCANNER_MANAGED_ASSET_LINK_EVENT,
        FINDING_REACHABILITY_SCOPE_LINK_EVENT,
        FINDING_BUSINESS_SERVICE_LINK_EVENT
    }

    /** Immutable provenance for an evidence reference that depends on an explicit identity link. */
    public record BindingReference(
            BindingKind bindingKind,
            UUID bindingId,
            String bindingSha256,
            String bindingSource,
            Instant recordedAt
    ) {
        public BindingReference {
            bindingKind = Objects.requireNonNull(bindingKind, "bindingKind");
            bindingId = Objects.requireNonNull(bindingId, "bindingId");
            bindingSha256 = requireSha(bindingSha256, "bindingSha256");
            bindingSource = requireText(bindingSource, "bindingSource", 256);
            recordedAt = Objects.requireNonNull(recordedAt, "recordedAt");
        }
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
            Set<NativeEvidenceIdentity> identities = new HashSet<>();
            for (EvidenceReference reference : evidenceReferences) {
                Objects.requireNonNull(reference, "evidenceReference");
                if (reference.dimension() != dimension) {
                    throw new IllegalArgumentException(
                            "Evidence reference dimension must match DimensionInput dimension");
                }
                NativeEvidenceIdentity identity = new NativeEvidenceIdentity(
                        reference.nativeEvidenceKind(),
                        reference.evidenceId()
                );
                if (!identities.add(identity)) {
                    throw new IllegalArgumentException(
                            "DimensionInput must not repeat a native evidence identity");
                }
                normalized.add(reference);
            }
            normalized.sort(Comparator
                    .comparing((EvidenceReference reference) ->
                            reference.nativeEvidenceKind().name())
                    .thenComparing(EvidenceReference::evidenceId));
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
            NativeEvidenceKind nativeEvidenceKind,
            UUID evidenceId,
            String evidenceSha256,
            String evidenceSource,
            Instant observedAt,
            BindingReference bindingReference
    ) {
        /** Historical V1-compatible constructor with dimension-derived native evidence kind. */
        public EvidenceReference(
                EvidenceDimension dimension,
                UUID evidenceId,
                String evidenceSha256,
                String evidenceSource,
                Instant observedAt
        ) {
            this(
                    dimension,
                    NativeEvidenceKind.defaultFor(dimension),
                    evidenceId,
                    evidenceSha256,
                    evidenceSource,
                    observedAt,
                    null
            );
        }

        public EvidenceReference {
            dimension = Objects.requireNonNull(dimension, "dimension");
            nativeEvidenceKind = Objects.requireNonNull(
                    nativeEvidenceKind,
                    "nativeEvidenceKind"
            );
            if (!nativeEvidenceKind.supports(dimension)) {
                throw new IllegalArgumentException(
                        "nativeEvidenceKind is incompatible with evidence dimension");
            }
            evidenceId = Objects.requireNonNull(evidenceId, "evidenceId");
            evidenceSha256 = requireSha(evidenceSha256, "evidenceSha256");
            evidenceSource = requireText(evidenceSource, "evidenceSource", 256);
            observedAt = Objects.requireNonNull(observedAt, "observedAt");
            validateBindingShape(nativeEvidenceKind, bindingReference);
        }
    }

    private static void validateBindingShape(
            NativeEvidenceKind nativeEvidenceKind,
            BindingReference bindingReference
    ) {
        switch (nativeEvidenceKind) {
            case MANAGED_ASSET_REVISION -> requireBindingKind(
                    bindingReference,
                    BindingKind.SCANNER_MANAGED_ASSET_LINK_EVENT,
                    "managed-asset evidence requires scanner-managed-asset link binding"
            );
            case NETWORK_REACHABILITY_EVIDENCE -> {
                if (bindingReference != null
                        && bindingReference.bindingKind()
                        != BindingKind.FINDING_REACHABILITY_SCOPE_LINK_EVENT) {
                    throw new IllegalArgumentException(
                            "network reachability evidence binding must be a Finding reachability-scope link event");
                }
            }
            case BUSINESS_IMPACT_EVIDENCE -> {
                if (bindingReference != null
                        && bindingReference.bindingKind()
                        != BindingKind.FINDING_BUSINESS_SERVICE_LINK_EVENT) {
                    throw new IllegalArgumentException(
                            "business impact evidence binding must be a Finding business-service link event");
                }
            }
            default -> {
                if (bindingReference != null) {
                    throw new IllegalArgumentException(
                            "bindingReference is not supported for this native evidence kind");
                }
            }
        }
    }

    private static void requireBindingKind(
            BindingReference bindingReference,
            BindingKind expected,
            String message
    ) {
        if (bindingReference == null || bindingReference.bindingKind() != expected) {
            throw new IllegalArgumentException(message);
        }
    }

    private static EnumMap<EvidenceDimension, DimensionInput> normalizeDimensions(
            Map<EvidenceDimension, DimensionInput> dimensions,
            Instant evaluatedAt,
            String contractId
    ) {
        Objects.requireNonNull(dimensions, "dimensions");
        EnumMap<EvidenceDimension, DimensionInput> normalized =
                new EnumMap<>(EvidenceDimension.class);
        normalized.putAll(dimensions);
        if (!normalized.keySet().equals(Set.of(EvidenceDimension.values()))) {
            throw new IllegalArgumentException(
                    "Decision input snapshot must classify every evidence dimension");
        }
        boolean v1 = V1_ID.equals(contractId);
        boolean v2 = V2_ID.equals(contractId);
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
                if (reference.bindingReference() != null
                        && reference.bindingReference().recordedAt().isAfter(evaluatedAt)) {
                    throw new IllegalArgumentException(
                            "Decision input must not reference a binding recorded after evaluatedAt");
                }
                if (v1 && (reference.nativeEvidenceKind()
                        != NativeEvidenceKind.defaultFor(reference.dimension())
                        || reference.bindingReference() != null)) {
                    throw new IllegalArgumentException(
                            "V1 Decision Input cannot contain typed alternate native evidence");
                }
                if (v2 && reference.nativeEvidenceKind()
                        != NativeEvidenceKind.MANAGED_ASSET_REVISION
                        && reference.bindingReference() != null) {
                    throw new IllegalArgumentException(
                            "V2 Decision Input only permits binding provenance for managed-asset revisions");
                }
                if (!v1 && !v2) {
                    validateV3Reference(reference);
                }
            }
        }
        return normalized;
    }

    private static void validateV3Reference(EvidenceReference reference) {
        switch (reference.nativeEvidenceKind()) {
            case NETWORK_REACHABILITY_EVIDENCE -> requireBindingKind(
                    reference.bindingReference(),
                    BindingKind.FINDING_REACHABILITY_SCOPE_LINK_EVENT,
                    "V3 network reachability evidence requires exact Finding reachability-scope binding"
            );
            case BUSINESS_IMPACT_EVIDENCE -> requireBindingKind(
                    reference.bindingReference(),
                    BindingKind.FINDING_BUSINESS_SERVICE_LINK_EVENT,
                    "V3 business impact evidence requires exact Finding business-service binding"
            );
            case MANAGED_ASSET_REVISION -> requireBindingKind(
                    reference.bindingReference(),
                    BindingKind.SCANNER_MANAGED_ASSET_LINK_EVENT,
                    "V3 managed-asset evidence requires scanner-managed-asset link binding"
            );
            default -> {
                if (reference.bindingReference() != null) {
                    throw new IllegalArgumentException(
                            "V3 binding provenance is not supported for this native evidence kind");
                }
            }
        }
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
            boolean typed = !V1_ID.equals(contractId);
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                writeString(output, canonicalPayloadFormatFor(contractId));
                writeString(output, contractId);
                writeString(output, semanticsFor(contractId));
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
                        if (typed) {
                            writeString(output, reference.nativeEvidenceKind().name());
                        }
                        output.writeLong(reference.evidenceId().getMostSignificantBits());
                        output.writeLong(reference.evidenceId().getLeastSignificantBits());
                        writeString(output, reference.evidenceSha256());
                        writeString(output, reference.evidenceSource());
                        output.writeLong(reference.observedAt().getEpochSecond());
                        output.writeInt(reference.observedAt().getNano());
                        if (typed) {
                            BindingReference binding = reference.bindingReference();
                            output.writeBoolean(binding != null);
                            if (binding != null) {
                                writeString(output, binding.bindingKind().name());
                                output.writeLong(binding.bindingId().getMostSignificantBits());
                                output.writeLong(binding.bindingId().getLeastSignificantBits());
                                writeString(output, binding.bindingSha256());
                                writeString(output, binding.bindingSource());
                                output.writeLong(binding.recordedAt().getEpochSecond());
                                output.writeInt(binding.recordedAt().getNano());
                            }
                        }
                    }
                }
            }
            return buffer.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException(
                    "Unexpected in-memory snapshot canonicalization failure",
                    exception
            );
        }
    }

    private static void requireContract(String contractId) {
        if (!V1_ID.equals(contractId) && !V2_ID.equals(contractId) && !V3_ID.equals(contractId)) {
            throw new IllegalArgumentException(
                    "contractId must be " + V1_ID + ", " + V2_ID + ", or " + V3_ID);
        }
    }

    private static String semanticsFor(String contractId) {
        requireContract(contractId);
        if (V3_ID.equals(contractId)) return V3_SEMANTICS;
        return V2_ID.equals(contractId) ? V2_SEMANTICS : V1_SEMANTICS;
    }

    private static String canonicalPayloadFormatFor(String contractId) {
        requireContract(contractId);
        if (V3_ID.equals(contractId)) return V3_CANONICAL_PAYLOAD_FORMAT;
        return V2_ID.equals(contractId)
                ? V2_CANONICAL_PAYLOAD_FORMAT
                : V1_CANONICAL_PAYLOAD_FORMAT;
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

    private static String requireText(String value, String field, int maximumLength) {
        if (value == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
        String normalized = value.trim();
        if (normalized.isEmpty()
                || normalized.length() > maximumLength
                || normalized.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return normalized;
    }

    private record NativeEvidenceIdentity(NativeEvidenceKind kind, UUID id) {
    }
}
