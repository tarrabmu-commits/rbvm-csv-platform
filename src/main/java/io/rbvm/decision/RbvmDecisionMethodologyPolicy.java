package io.rbvm.decision;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Versioned policy boundary for selecting independent evidence before any RBVM formula exists.
 *
 * <p>This model deliberately contains no risk weights, risk score, priority tier, remediation SLA,
 * source precedence, or evidence-combination formula. It only makes the evaluation grain and the
 * admissible evidence-selection/freshness rules explicit.</p>
 */
public record RbvmDecisionMethodologyPolicy(
        String contractId,
        int revision,
        String policySha256,
        SubjectScope subjectScope,
        MissingEvidenceHandling missingEvidenceHandling,
        AmbiguityHandling ambiguityHandling,
        LegacyPriorityHandling legacyPriorityHandling,
        Map<EvidenceDimension, EvidenceSelectionPolicy> evidencePolicies
) {
    public static final String ID = "RBVM_DECISION_METHODOLOGY_V1";
    public static final String SEMANTICS =
            "FINDING_SCOPED_EXPLICIT_EVIDENCE_SELECTION_POLICY";
    public static final String CANONICAL_PAYLOAD_FORMAT =
            "RBVM_DECISION_METHODOLOGY_CANONICAL_BINARY_V1";

    public RbvmDecisionMethodologyPolicy {
        contractId = requireExact(contractId, ID, "contractId");
        if (revision < 1) {
            throw new IllegalArgumentException("revision must be positive");
        }
        subjectScope = Objects.requireNonNull(subjectScope, "subjectScope");
        missingEvidenceHandling = Objects.requireNonNull(
                missingEvidenceHandling,
                "missingEvidenceHandling"
        );
        ambiguityHandling = Objects.requireNonNull(ambiguityHandling, "ambiguityHandling");
        legacyPriorityHandling = Objects.requireNonNull(
                legacyPriorityHandling,
                "legacyPriorityHandling"
        );

        if (subjectScope != SubjectScope.FINDING) {
            throw new IllegalArgumentException(
                    "RBVM_DECISION_METHODOLOGY_V1 evaluates canonical Finding_ID only");
        }
        if (missingEvidenceHandling != MissingEvidenceHandling.PRESERVE_UNKNOWN) {
            throw new IllegalArgumentException("Missing evidence must remain UNKNOWN");
        }
        if (ambiguityHandling != AmbiguityHandling.PRESERVE_AMBIGUOUS) {
            throw new IllegalArgumentException("Ambiguous multi-source evidence must remain ambiguous");
        }
        if (legacyPriorityHandling != LegacyPriorityHandling.EXCLUDE_LEGACY_PRIORITY_TIER) {
            throw new IllegalArgumentException(
                    "Legacy vulnerability.priority_tier must not enter RBVM methodology input");
        }

        EnumMap<EvidenceDimension, EvidenceSelectionPolicy> normalized =
                normalizePolicies(evidencePolicies);
        evidencePolicies = Collections.unmodifiableMap(normalized);
        policySha256 = requireSha256(policySha256);
        String expectedSha256 = canonicalSha256(
                contractId,
                revision,
                subjectScope,
                missingEvidenceHandling,
                ambiguityHandling,
                legacyPriorityHandling,
                normalized
        );
        if (!policySha256.equals(expectedSha256)) {
            throw new IllegalArgumentException(
                    "policySha256 does not match the canonical policy payload");
        }
    }

    /** Creates a policy with a SHA-256 derived from its canonical payload. */
    public static RbvmDecisionMethodologyPolicy create(
            int revision,
            SubjectScope subjectScope,
            MissingEvidenceHandling missingEvidenceHandling,
            AmbiguityHandling ambiguityHandling,
            LegacyPriorityHandling legacyPriorityHandling,
            Map<EvidenceDimension, EvidenceSelectionPolicy> evidencePolicies
    ) {
        EnumMap<EvidenceDimension, EvidenceSelectionPolicy> normalized =
                normalizePolicies(evidencePolicies);
        String sha256 = canonicalSha256(
                ID,
                revision,
                subjectScope,
                missingEvidenceHandling,
                ambiguityHandling,
                legacyPriorityHandling,
                normalized
        );
        return new RbvmDecisionMethodologyPolicy(
                ID,
                revision,
                sha256,
                subjectScope,
                missingEvidenceHandling,
                ambiguityHandling,
                legacyPriorityHandling,
                normalized
        );
    }

    public String semantics() {
        return SEMANTICS;
    }

    /**
     * Returns deterministic binary policy bytes used for provenance hashing. The payload excludes
     * policySha256 itself, preventing a self-referential hash. String values use length-prefixed
     * UTF-8 and evidence dimensions are encoded in enum order.
     */
    public byte[] canonicalPayload() {
        return canonicalPayload(
                contractId,
                revision,
                subjectScope,
                missingEvidenceHandling,
                ambiguityHandling,
                legacyPriorityHandling,
                evidencePolicies
        );
    }

    public enum SubjectScope {
        FINDING
    }

    public enum EvidenceDimension {
        APPLICABILITY,
        TECHNICAL_SEVERITY,
        KNOWN_EXPLOITATION,
        EXPLOITATION_PROBABILITY,
        ASSET_CONTEXT,
        NETWORK_REACHABILITY,
        BUSINESS_MISSION_IMPACT
    }

    public enum MissingEvidenceHandling {
        PRESERVE_UNKNOWN
    }

    public enum AmbiguityHandling {
        PRESERVE_AMBIGUOUS
    }

    public enum LegacyPriorityHandling {
        EXCLUDE_LEGACY_PRIORITY_TIER
    }

    public enum SourceSelectionMode {
        ALL_SOURCES,
        EXPLICIT_ALLOWLIST
    }

    public enum FreshnessMode {
        NO_AGE_LIMIT,
        MAX_AGE_SECONDS
    }

    /**
     * Explicit per-dimension selection rules. An allowlist filters admissible sources but does not
     * rank or choose a winner among multiple allowed sources. Allowlist order is canonicalized
     * lexicographically because order carries no precedence semantic.
     */
    public record EvidenceSelectionPolicy(
            EvidenceDimension dimension,
            SourceSelectionMode sourceSelectionMode,
            List<String> sourceAllowlist,
            FreshnessMode freshnessMode,
            Long maximumAgeSeconds
    ) {
        public EvidenceSelectionPolicy {
            dimension = Objects.requireNonNull(dimension, "dimension");
            sourceSelectionMode = Objects.requireNonNull(
                    sourceSelectionMode,
                    "sourceSelectionMode"
            );
            freshnessMode = Objects.requireNonNull(freshnessMode, "freshnessMode");
            Objects.requireNonNull(sourceAllowlist, "sourceAllowlist");

            List<String> normalizedSources = new ArrayList<>(sourceAllowlist.size());
            Set<String> seen = new HashSet<>();
            for (String source : sourceAllowlist) {
                String normalized = requireSource(source);
                if (!seen.add(normalized)) {
                    throw new IllegalArgumentException("sourceAllowlist contains a duplicate source");
                }
                normalizedSources.add(normalized);
            }
            normalizedSources.sort(String::compareTo);
            sourceAllowlist = List.copyOf(normalizedSources);

            if (sourceSelectionMode == SourceSelectionMode.ALL_SOURCES
                    && !sourceAllowlist.isEmpty()) {
                throw new IllegalArgumentException(
                        "ALL_SOURCES must not carry a source allowlist");
            }
            if (sourceSelectionMode == SourceSelectionMode.EXPLICIT_ALLOWLIST
                    && sourceAllowlist.isEmpty()) {
                throw new IllegalArgumentException(
                        "EXPLICIT_ALLOWLIST requires at least one source");
            }

            if (freshnessMode == FreshnessMode.NO_AGE_LIMIT && maximumAgeSeconds != null) {
                throw new IllegalArgumentException(
                        "NO_AGE_LIMIT must not carry maximumAgeSeconds");
            }
            if (freshnessMode == FreshnessMode.MAX_AGE_SECONDS
                    && (maximumAgeSeconds == null || maximumAgeSeconds < 1)) {
                throw new IllegalArgumentException(
                        "MAX_AGE_SECONDS requires a positive maximumAgeSeconds");
            }
        }
    }

    private static EnumMap<EvidenceDimension, EvidenceSelectionPolicy> normalizePolicies(
            Map<EvidenceDimension, EvidenceSelectionPolicy> evidencePolicies
    ) {
        Objects.requireNonNull(evidencePolicies, "evidencePolicies");
        EnumMap<EvidenceDimension, EvidenceSelectionPolicy> normalized =
                new EnumMap<>(EvidenceDimension.class);
        normalized.putAll(evidencePolicies);
        if (!normalized.keySet().equals(Set.of(EvidenceDimension.values()))) {
            throw new IllegalArgumentException(
                    "Every independent evidence dimension must have an explicit selection policy");
        }
        for (Map.Entry<EvidenceDimension, EvidenceSelectionPolicy> entry : normalized.entrySet()) {
            if (entry.getValue() == null || entry.getValue().dimension() != entry.getKey()) {
                throw new IllegalArgumentException(
                        "Evidence policy map key must match the policy dimension");
            }
        }
        return normalized;
    }

    private static String canonicalSha256(
            String contractId,
            int revision,
            SubjectScope subjectScope,
            MissingEvidenceHandling missingEvidenceHandling,
            AmbiguityHandling ambiguityHandling,
            LegacyPriorityHandling legacyPriorityHandling,
            Map<EvidenceDimension, EvidenceSelectionPolicy> evidencePolicies
    ) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(canonicalPayload(
                    contractId,
                    revision,
                    subjectScope,
                    missingEvidenceHandling,
                    ambiguityHandling,
                    legacyPriorityHandling,
                    evidencePolicies
            )));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    private static byte[] canonicalPayload(
            String contractId,
            int revision,
            SubjectScope subjectScope,
            MissingEvidenceHandling missingEvidenceHandling,
            AmbiguityHandling ambiguityHandling,
            LegacyPriorityHandling legacyPriorityHandling,
            Map<EvidenceDimension, EvidenceSelectionPolicy> evidencePolicies
    ) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                writeString(output, CANONICAL_PAYLOAD_FORMAT);
                writeString(output, contractId);
                writeString(output, SEMANTICS);
                output.writeInt(revision);
                writeString(output, subjectScope.name());
                writeString(output, missingEvidenceHandling.name());
                writeString(output, ambiguityHandling.name());
                writeString(output, legacyPriorityHandling.name());
                for (EvidenceDimension dimension : EvidenceDimension.values()) {
                    EvidenceSelectionPolicy policy = Objects.requireNonNull(
                            evidencePolicies.get(dimension),
                            "Missing canonical evidence policy for " + dimension
                    );
                    writeString(output, dimension.name());
                    writeString(output, policy.sourceSelectionMode().name());
                    writeString(output, policy.freshnessMode().name());
                    output.writeLong(
                            policy.maximumAgeSeconds() == null ? -1L : policy.maximumAgeSeconds());
                    output.writeInt(policy.sourceAllowlist().size());
                    for (String source : policy.sourceAllowlist()) {
                        writeString(output, source);
                    }
                }
            }
            return buffer.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException("Unexpected in-memory canonicalization failure", exception);
        }
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static String requireExact(String value, String expected, String field) {
        if (!expected.equals(value)) {
            throw new IllegalArgumentException(field + " must be " + expected);
        }
        return value;
    }

    private static String requireSha256(String value) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("policySha256 must be lowercase SHA-256");
        }
        return value;
    }

    private static String requireSource(String value) {
        if (value == null) {
            throw new IllegalArgumentException("sourceAllowlist must not contain null");
        }
        String normalized = value.trim();
        if (normalized.isEmpty() || normalized.length() > 256 || normalized.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException("sourceAllowlist contains an invalid source");
        }
        return normalized;
    }
}
