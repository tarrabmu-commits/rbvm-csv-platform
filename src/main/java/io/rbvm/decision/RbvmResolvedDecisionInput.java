package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Ephemeral typed native values for exactly the evidence references in one immutable Decision Input
 * Snapshot. This object adds no evidence, chooses no winner, and calculates no decision output.
 */
public record RbvmResolvedDecisionInput(
        RbvmDecisionInputSnapshot snapshot,
        Map<EvidenceDimension, List<ResolvedEvidence>> evidenceByDimension
) {
    public RbvmResolvedDecisionInput {
        snapshot = Objects.requireNonNull(snapshot, "snapshot");
        Objects.requireNonNull(evidenceByDimension, "evidenceByDimension");

        EnumMap<EvidenceDimension, List<ResolvedEvidence>> normalized =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            List<ResolvedEvidence> values = evidenceByDimension.get(dimension);
            if (values == null) {
                throw new IllegalArgumentException(
                        "Every Decision Input evidence dimension must be resolved explicitly");
            }
            normalized.put(
                    dimension,
                    validateDimension(snapshot, dimension, values)
            );
        }
        if (evidenceByDimension.size() != EvidenceDimension.values().length) {
            throw new IllegalArgumentException("Resolved Decision Input contains an unknown dimension");
        }
        evidenceByDimension = Collections.unmodifiableMap(normalized);
    }

    public List<ResolvedEvidence> evidence(EvidenceDimension dimension) {
        return evidenceByDimension.get(Objects.requireNonNull(dimension, "dimension"));
    }

    private static List<ResolvedEvidence> validateDimension(
            RbvmDecisionInputSnapshot snapshot,
            EvidenceDimension dimension,
            List<ResolvedEvidence> input
    ) {
        Objects.requireNonNull(input, "resolved evidence list");
        List<EvidenceReference> expectedReferences =
                snapshot.dimensions().get(dimension).evidenceReferences();
        DimensionState state = snapshot.dimensions().get(dimension).state();

        if (state == DimensionState.MISSING && !input.isEmpty()) {
            throw new IllegalArgumentException("MISSING dimension cannot resolve native evidence");
        }
        if (input.size() != expectedReferences.size()) {
            throw new IllegalArgumentException(
                    "Resolved evidence count must exactly match Decision Input Snapshot references");
        }

        Map<NativeEvidenceIdentity, EvidenceReference> expectedById = new HashMap<>();
        for (EvidenceReference reference : expectedReferences) {
            expectedById.put(identity(reference), reference);
        }

        Set<NativeEvidenceIdentity> seen = new HashSet<>();
        List<ResolvedEvidence> normalized = new ArrayList<>(input.size());
        for (ResolvedEvidence evidence : input) {
            Objects.requireNonNull(evidence, "resolved evidence");
            EvidenceReference reference = evidence.reference();
            if (reference.dimension() != dimension) {
                throw new IllegalArgumentException(
                        "Resolved evidence dimension must match its snapshot dimension");
            }
            NativeEvidenceIdentity identity = identity(reference);
            if (!seen.add(identity)) {
                throw new IllegalArgumentException(
                        "Resolved evidence contains a duplicate native identity");
            }
            EvidenceReference expected = expectedById.get(identity);
            if (!reference.equals(expected)) {
                throw new IllegalArgumentException(
                        "Resolved evidence provenance must exactly match its snapshot reference");
            }
            normalized.add(evidence);
        }
        normalized.sort(Comparator
                .comparing((ResolvedEvidence value) ->
                        value.reference().nativeEvidenceKind().name())
                .thenComparing(value -> value.reference().evidenceId()));
        return List.copyOf(normalized);
    }

    private static NativeEvidenceIdentity identity(EvidenceReference reference) {
        return new NativeEvidenceIdentity(
                reference.nativeEvidenceKind(),
                reference.evidenceId()
        );
    }

    private record NativeEvidenceIdentity(
            RbvmDecisionInputSnapshot.NativeEvidenceKind nativeEvidenceKind,
            UUID evidenceId
    ) {
    }

    public sealed interface ResolvedEvidence permits
            ApplicabilityEvidenceValue,
            TechnicalSeverityEvidenceValue,
            KnownExploitationEvidenceValue,
            ExploitationProbabilityEvidenceValue,
            AssetContextEvidenceValue,
            NetworkReachabilityEvidenceValue,
            BusinessMissionImpactEvidenceValue {
        EvidenceReference reference();
    }

    public enum ApplicabilityStatus {
        APPLICABLE,
        NOT_APPLICABLE,
        UNKNOWN
    }

    public record ApplicabilityEvidenceValue(
            EvidenceReference reference,
            ApplicabilityStatus status,
            String reason
    ) implements ResolvedEvidence {
        public ApplicabilityEvidenceValue {
            reference = requireReference(reference, EvidenceDimension.APPLICABILITY);
            status = Objects.requireNonNull(status, "status");
            reason = requireText(reason, "reason");
        }
    }

    public record TechnicalSeverityEvidenceValue(
            EvidenceReference reference,
            String cvssVersion,
            BigDecimal baseScore,
            String vector
    ) implements ResolvedEvidence {
        public TechnicalSeverityEvidenceValue {
            reference = requireReference(reference, EvidenceDimension.TECHNICAL_SEVERITY);
            if (!"3.1".equals(cvssVersion)) {
                throw new IllegalArgumentException("CVSS version must be 3.1");
            }
            baseScore = requireRange(baseScore, BigDecimal.ZERO, BigDecimal.TEN, "baseScore");
            vector = requireText(vector, "vector");
            if (!vector.startsWith("CVSS:3.1/")) {
                throw new IllegalArgumentException("CVSS vector must use CVSS:3.1");
            }
        }
    }

    public enum KevStatus {
        LISTED,
        NOT_LISTED
    }

    public enum KnownRansomwareCampaignUse {
        KNOWN,
        UNKNOWN
    }

    public record KnownExploitationEvidenceValue(
            EvidenceReference reference,
            KevStatus status,
            LocalDate dateAdded,
            LocalDate dueDate,
            KnownRansomwareCampaignUse knownRansomwareCampaignUse
    ) implements ResolvedEvidence {
        public KnownExploitationEvidenceValue {
            reference = requireReference(reference, EvidenceDimension.KNOWN_EXPLOITATION);
            status = Objects.requireNonNull(status, "status");
            if (status == KevStatus.LISTED) {
                Objects.requireNonNull(dateAdded, "dateAdded");
                Objects.requireNonNull(dueDate, "dueDate");
                Objects.requireNonNull(
                        knownRansomwareCampaignUse,
                        "knownRansomwareCampaignUse"
                );
            } else if (dateAdded != null || dueDate != null || knownRansomwareCampaignUse != null) {
                throw new IllegalArgumentException(
                        "NOT_LISTED KEV evidence must not carry listing metadata");
            }
        }
    }

    public record ExploitationProbabilityEvidenceValue(
            EvidenceReference reference,
            BigDecimal probability,
            BigDecimal percentile,
            String modelVersion,
            LocalDate scoreDate
    ) implements ResolvedEvidence {
        public ExploitationProbabilityEvidenceValue {
            reference = requireReference(
                    reference,
                    EvidenceDimension.EXPLOITATION_PROBABILITY
            );
            probability = requireRange(
                    probability,
                    BigDecimal.ZERO,
                    BigDecimal.ONE,
                    "probability"
            );
            percentile = requireRange(
                    percentile,
                    BigDecimal.ZERO,
                    BigDecimal.ONE,
                    "percentile"
            );
            modelVersion = requireText(modelVersion, "modelVersion");
            if (!modelVersion.matches("v?[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}")) {
                throw new IllegalArgumentException("modelVersion is not a canonical EPSS model date");
            }
            scoreDate = Objects.requireNonNull(scoreDate, "scoreDate");
        }
    }

    public enum Environment {
        PRODUCTION,
        PRE_PRODUCTION,
        DEVELOPMENT,
        TEST,
        SANDBOX,
        DISASTER_RECOVERY,
        UNKNOWN
    }

    public enum BusinessCriticality {
        MISSION_CRITICAL,
        HIGH,
        MODERATE,
        LOW,
        UNKNOWN
    }

    public record AssetContextEvidenceValue(
            EvidenceReference reference,
            Environment environment,
            String businessService,
            String businessOwner,
            BusinessCriticality businessCriticality
    ) implements ResolvedEvidence {
        public AssetContextEvidenceValue {
            reference = requireReference(reference, EvidenceDimension.ASSET_CONTEXT);
            environment = Objects.requireNonNull(environment, "environment");
            businessService = requireText(businessService, "businessService");
            businessOwner = requireText(businessOwner, "businessOwner");
            businessCriticality = Objects.requireNonNull(
                    businessCriticality,
                    "businessCriticality"
            );
        }
    }

    public enum OriginScope {
        INTERNET,
        EXTERNAL_PARTNER,
        INTERNAL_ENTERPRISE,
        LOCAL_SEGMENT,
        OTHER,
        UNKNOWN
    }

    public enum TransportProtocol {
        TCP,
        UDP,
        ICMP,
        OTHER,
        UNKNOWN
    }

    public enum ReachabilityStatus {
        REACHABLE,
        NOT_REACHABLE,
        UNKNOWN
    }

    public enum ReachabilityMethod {
        ACTIVE_PROBE,
        CONTROL_PLANE,
        FIREWALL_POLICY,
        CLOUD_CONFIGURATION,
        PASSIVE_OBSERVATION,
        OTHER,
        UNKNOWN
    }

    public record NetworkReachabilityEvidenceValue(
            EvidenceReference reference,
            OriginScope originScope,
            String originLabel,
            TransportProtocol transportProtocol,
            Integer targetPort,
            String targetService,
            ReachabilityStatus reachabilityStatus,
            ReachabilityMethod reachabilityMethod
    ) implements ResolvedEvidence {
        public NetworkReachabilityEvidenceValue {
            reference = requireReference(reference, EvidenceDimension.NETWORK_REACHABILITY);
            originScope = Objects.requireNonNull(originScope, "originScope");
            originLabel = requireText(originLabel, "originLabel");
            transportProtocol = Objects.requireNonNull(transportProtocol, "transportProtocol");
            if (targetPort != null && (targetPort < 1 || targetPort > 65535)) {
                throw new IllegalArgumentException("targetPort must be between 1 and 65535");
            }
            if ((transportProtocol == TransportProtocol.TCP
                    || transportProtocol == TransportProtocol.UDP) && targetPort == null) {
                throw new IllegalArgumentException("TCP/UDP reachability requires targetPort");
            }
            if (transportProtocol == TransportProtocol.ICMP && targetPort != null) {
                throw new IllegalArgumentException("ICMP reachability must not carry targetPort");
            }
            targetService = requireText(targetService, "targetService");
            reachabilityStatus = Objects.requireNonNull(reachabilityStatus, "reachabilityStatus");
            reachabilityMethod = Objects.requireNonNull(reachabilityMethod, "reachabilityMethod");
        }
    }

    public enum ImpactDimension {
        AVAILABILITY,
        INTEGRITY,
        CONFIDENTIALITY,
        SAFETY,
        FINANCIAL,
        REGULATORY,
        OPERATIONAL,
        REPUTATIONAL,
        MISSION,
        OTHER,
        UNKNOWN
    }

    public enum ImpactLevel {
        SEVERE,
        HIGH,
        MODERATE,
        LOW,
        NEGLIGIBLE,
        UNKNOWN
    }

    public enum ImpactMethod {
        BUSINESS_IMPACT_ANALYSIS,
        SERVICE_OWNER_ATTESTATION,
        POLICY_CLASSIFICATION,
        INCIDENT_ANALYSIS,
        OTHER,
        UNKNOWN
    }

    public record BusinessMissionImpactEvidenceValue(
            EvidenceReference reference,
            String businessService,
            String businessServiceNormalized,
            ImpactDimension impactDimension,
            ImpactLevel impactLevel,
            ImpactMethod impactMethod,
            String impactStatement
    ) implements ResolvedEvidence {
        public BusinessMissionImpactEvidenceValue {
            reference = requireReference(
                    reference,
                    EvidenceDimension.BUSINESS_MISSION_IMPACT
            );
            businessService = requireText(businessService, "businessService");
            businessServiceNormalized = requireText(
                    businessServiceNormalized,
                    "businessServiceNormalized"
            );
            impactDimension = Objects.requireNonNull(impactDimension, "impactDimension");
            impactLevel = Objects.requireNonNull(impactLevel, "impactLevel");
            impactMethod = Objects.requireNonNull(impactMethod, "impactMethod");
            impactStatement = requireText(impactStatement, "impactStatement");
        }
    }

    private static EvidenceReference requireReference(
            EvidenceReference reference,
            EvidenceDimension expectedDimension
    ) {
        Objects.requireNonNull(reference, "reference");
        if (reference.dimension() != expectedDimension) {
            throw new IllegalArgumentException(
                    "Resolved evidence reference dimension must be " + expectedDimension);
        }
        return reference;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.trim().isEmpty() || value.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " must be non-empty text");
        }
        return value.trim();
    }

    private static BigDecimal requireRange(
            BigDecimal value,
            BigDecimal minimum,
            BigDecimal maximum,
            String field
    ) {
        Objects.requireNonNull(value, field);
        if (value.compareTo(minimum) < 0 || value.compareTo(maximum) > 0) {
            throw new IllegalArgumentException(
                    field + " must be between " + minimum + " and " + maximum);
        }
        return value;
    }
}
