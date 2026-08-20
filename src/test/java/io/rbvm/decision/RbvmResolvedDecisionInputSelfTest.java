package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.AssetContextEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.BusinessCriticality;
import io.rbvm.decision.RbvmResolvedDecisionInput.BusinessMissionImpactEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.Environment;
import io.rbvm.decision.RbvmResolvedDecisionInput.ExploitationProbabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ImpactDimension;
import io.rbvm.decision.RbvmResolvedDecisionInput.ImpactLevel;
import io.rbvm.decision.RbvmResolvedDecisionInput.ImpactMethod;
import io.rbvm.decision.RbvmResolvedDecisionInput.KevStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.KnownExploitationEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.KnownRansomwareCampaignUse;
import io.rbvm.decision.RbvmResolvedDecisionInput.NetworkReachabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.OriginScope;
import io.rbvm.decision.RbvmResolvedDecisionInput.ReachabilityMethod;
import io.rbvm.decision.RbvmResolvedDecisionInput.ReachabilityStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.ResolvedEvidence;
import io.rbvm.decision.RbvmResolvedDecisionInput.TechnicalSeverityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.TransportProtocol;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class RbvmResolvedDecisionInputSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-20T04:30:00Z");
    private static final String POLICY_SHA = "a".repeat(64);

    private RbvmResolvedDecisionInputSelfTest() {
    }

    public static void main(String[] args) {
        resolvesExactlyTheSnapshotReferences();
        canonicalizesResolvedEvidenceByNativeUuid();
        rejectsDroppedInjectedOrMutatedProvenance();
        rejectsNativeValueShapesOutsideEvidenceContracts();
        System.out.println("RbvmResolvedDecisionInputSelfTest: PASS");
    }

    private static void resolvesExactlyTheSnapshotReferences() {
        Fixture fixture = fixture(false);
        RbvmResolvedDecisionInput resolved = new RbvmResolvedDecisionInput(
                fixture.snapshot(),
                fixture.values()
        );

        assert resolved.snapshot().snapshotSha256().equals(fixture.snapshot().snapshotSha256());
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            assert resolved.evidence(dimension).size()
                    == fixture.snapshot().dimensions().get(dimension).evidenceReferences().size();
            for (ResolvedEvidence value : resolved.evidence(dimension)) {
                assert fixture.snapshot().dimensions().get(dimension).evidenceReferences()
                        .contains(value.reference());
            }
        }

        ApplicabilityEvidenceValue applicability = (ApplicabilityEvidenceValue)
                resolved.evidence(EvidenceDimension.APPLICABILITY).get(0);
        assert applicability.status() == ApplicabilityStatus.APPLICABLE;

        TechnicalSeverityEvidenceValue cvss = (TechnicalSeverityEvidenceValue)
                resolved.evidence(EvidenceDimension.TECHNICAL_SEVERITY).get(0);
        assert cvss.baseScore().compareTo(new BigDecimal("9.8")) == 0;

        KnownExploitationEvidenceValue kev = (KnownExploitationEvidenceValue)
                resolved.evidence(EvidenceDimension.KNOWN_EXPLOITATION).get(0);
        assert kev.status() == KevStatus.LISTED;

        ExploitationProbabilityEvidenceValue epss = (ExploitationProbabilityEvidenceValue)
                resolved.evidence(EvidenceDimension.EXPLOITATION_PROBABILITY).get(0);
        assert epss.probability().compareTo(new BigDecimal("0.42")) == 0;

        AssetContextEvidenceValue context = (AssetContextEvidenceValue)
                resolved.evidence(EvidenceDimension.ASSET_CONTEXT).get(0);
        assert context.environment() == Environment.PRODUCTION;

        NetworkReachabilityEvidenceValue reachability = (NetworkReachabilityEvidenceValue)
                resolved.evidence(EvidenceDimension.NETWORK_REACHABILITY).get(0);
        assert reachability.targetPort() == 443;

        BusinessMissionImpactEvidenceValue impact = (BusinessMissionImpactEvidenceValue)
                resolved.evidence(EvidenceDimension.BUSINESS_MISSION_IMPACT).get(0);
        assert impact.impactLevel() == ImpactLevel.SEVERE;
    }

    private static void canonicalizesResolvedEvidenceByNativeUuid() {
        Fixture fixture = fixture(true);
        RbvmResolvedDecisionInput resolved = new RbvmResolvedDecisionInput(
                fixture.snapshot(),
                fixture.values()
        );
        List<ResolvedEvidence> reachability =
                resolved.evidence(EvidenceDimension.NETWORK_REACHABILITY);
        assert reachability.size() == 2;
        assert reachability.get(0).reference().evidenceId()
                .compareTo(reachability.get(1).reference().evidenceId()) < 0;
    }

    private static void rejectsDroppedInjectedOrMutatedProvenance() {
        Fixture fixture = fixture(false);

        EnumMap<EvidenceDimension, List<ResolvedEvidence>> dropped = copy(fixture.values());
        dropped.put(EvidenceDimension.TECHNICAL_SEVERITY, List.of());
        assertRejected(() -> new RbvmResolvedDecisionInput(fixture.snapshot(), dropped),
                "count must exactly match");

        EnumMap<EvidenceDimension, List<ResolvedEvidence>> injected = copy(fixture.values());
        EvidenceReference extraReference = reference(
                EvidenceDimension.TECHNICAL_SEVERITY,
                "injected",
                90
        );
        List<ResolvedEvidence> extraValues = new ArrayList<>(
                injected.get(EvidenceDimension.TECHNICAL_SEVERITY));
        extraValues.add(new TechnicalSeverityEvidenceValue(
                extraReference,
                "3.1",
                new BigDecimal("5.0"),
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
        ));
        injected.put(EvidenceDimension.TECHNICAL_SEVERITY, List.copyOf(extraValues));
        assertRejected(() -> new RbvmResolvedDecisionInput(fixture.snapshot(), injected),
                "count must exactly match");

        EnumMap<EvidenceDimension, List<ResolvedEvidence>> mutated = copy(fixture.values());
        EvidenceReference original = fixture.snapshot().dimensions()
                .get(EvidenceDimension.APPLICABILITY).evidenceReferences().get(0);
        EvidenceReference wrongSha = new EvidenceReference(
                original.dimension(),
                original.evidenceId(),
                "f".repeat(64),
                original.evidenceSource(),
                original.observedAt()
        );
        mutated.put(
                EvidenceDimension.APPLICABILITY,
                List.of(new ApplicabilityEvidenceValue(
                        wrongSha,
                        ApplicabilityStatus.APPLICABLE,
                        "package is deployed"
                ))
        );
        assertRejected(() -> new RbvmResolvedDecisionInput(fixture.snapshot(), mutated),
                "provenance must exactly match");

        EnumMap<EvidenceDimension, List<ResolvedEvidence>> unknownDimension = copy(fixture.values());
        unknownDimension.remove(EvidenceDimension.ASSET_CONTEXT);
        assertRejected(() -> new RbvmResolvedDecisionInput(fixture.snapshot(), unknownDimension),
                "every decision input evidence dimension");
    }

    private static void rejectsNativeValueShapesOutsideEvidenceContracts() {
        EvidenceReference cvss = reference(EvidenceDimension.TECHNICAL_SEVERITY, "cvss", 101);
        assertRejected(() -> new TechnicalSeverityEvidenceValue(
                cvss,
                "3.1",
                new BigDecimal("10.1"),
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        ), "basescore");

        EvidenceReference kev = reference(EvidenceDimension.KNOWN_EXPLOITATION, "kev", 102);
        assertRejected(() -> new KnownExploitationEvidenceValue(
                kev,
                KevStatus.NOT_LISTED,
                LocalDate.parse("2026-01-01"),
                null,
                null
        ), "must not carry listing metadata");

        EvidenceReference epss = reference(
                EvidenceDimension.EXPLOITATION_PROBABILITY, "epss", 103);
        assertRejected(() -> new ExploitationProbabilityEvidenceValue(
                epss,
                new BigDecimal("-0.01"),
                new BigDecimal("0.90"),
                "2026.08.20",
                LocalDate.parse("2026-08-20")
        ), "probability");

        EvidenceReference reachability = reference(
                EvidenceDimension.NETWORK_REACHABILITY, "reachability", 104);
        assertRejected(() -> new NetworkReachabilityEvidenceValue(
                reachability,
                OriginScope.INTERNET,
                "edge",
                TransportProtocol.TCP,
                null,
                "https",
                ReachabilityStatus.REACHABLE,
                ReachabilityMethod.ACTIVE_PROBE
        ), "requires targetport");
    }

    private static Fixture fixture(boolean twoReachabilityReferences) {
        EnumMap<EvidenceDimension, DimensionInput> dimensions =
                new EnumMap<>(EvidenceDimension.class);
        EnumMap<EvidenceDimension, List<ResolvedEvidence>> values =
                new EnumMap<>(EvidenceDimension.class);

        EvidenceReference applicability = reference(EvidenceDimension.APPLICABILITY, "app", 1);
        put(dimensions, values, EvidenceDimension.APPLICABILITY,
                List.of(applicability),
                List.of(new ApplicabilityEvidenceValue(
                        applicability, ApplicabilityStatus.APPLICABLE, "package is deployed")));

        EvidenceReference cvss = reference(EvidenceDimension.TECHNICAL_SEVERITY, "cvss", 2);
        put(dimensions, values, EvidenceDimension.TECHNICAL_SEVERITY,
                List.of(cvss),
                List.of(new TechnicalSeverityEvidenceValue(
                        cvss,
                        "3.1",
                        new BigDecimal("9.8"),
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")));

        EvidenceReference kev = reference(EvidenceDimension.KNOWN_EXPLOITATION, "kev", 3);
        put(dimensions, values, EvidenceDimension.KNOWN_EXPLOITATION,
                List.of(kev),
                List.of(new KnownExploitationEvidenceValue(
                        kev,
                        KevStatus.LISTED,
                        LocalDate.parse("2026-08-01"),
                        LocalDate.parse("2026-08-22"),
                        KnownRansomwareCampaignUse.KNOWN)));

        EvidenceReference epss = reference(
                EvidenceDimension.EXPLOITATION_PROBABILITY, "epss", 4);
        put(dimensions, values, EvidenceDimension.EXPLOITATION_PROBABILITY,
                List.of(epss),
                List.of(new ExploitationProbabilityEvidenceValue(
                        epss,
                        new BigDecimal("0.42"),
                        new BigDecimal("0.93"),
                        "2026.08.20",
                        LocalDate.parse("2026-08-20"))));

        EvidenceReference context = reference(EvidenceDimension.ASSET_CONTEXT, "context", 5);
        put(dimensions, values, EvidenceDimension.ASSET_CONTEXT,
                List.of(context),
                List.of(new AssetContextEvidenceValue(
                        context,
                        Environment.PRODUCTION,
                        "Payments",
                        "payments-owner",
                        BusinessCriticality.MISSION_CRITICAL)));

        EvidenceReference reachabilityA = reference(
                EvidenceDimension.NETWORK_REACHABILITY, "reach-a", 6);
        List<EvidenceReference> reachabilityReferences;
        List<ResolvedEvidence> reachabilityValues = new ArrayList<>();
        reachabilityValues.add(new NetworkReachabilityEvidenceValue(
                reachabilityA,
                OriginScope.INTERNET,
                "external-edge",
                TransportProtocol.TCP,
                443,
                "https",
                ReachabilityStatus.REACHABLE,
                ReachabilityMethod.ACTIVE_PROBE
        ));
        if (twoReachabilityReferences) {
            EvidenceReference reachabilityB = reference(
                    EvidenceDimension.NETWORK_REACHABILITY, "reach-b", 7);
            reachabilityReferences = List.of(reachabilityB, reachabilityA);
            reachabilityValues.add(new NetworkReachabilityEvidenceValue(
                    reachabilityB,
                    OriginScope.INTERNAL_ENTERPRISE,
                    "corp",
                    TransportProtocol.TCP,
                    8443,
                    "https-alt",
                    ReachabilityStatus.REACHABLE,
                    ReachabilityMethod.FIREWALL_POLICY
            ));
        } else {
            reachabilityReferences = List.of(reachabilityA);
        }
        dimensions.put(
                EvidenceDimension.NETWORK_REACHABILITY,
                new DimensionInput(
                        EvidenceDimension.NETWORK_REACHABILITY,
                        twoReachabilityReferences ? DimensionState.AMBIGUOUS : DimensionState.PRESENT,
                        reachabilityReferences
                )
        );
        values.put(EvidenceDimension.NETWORK_REACHABILITY, List.copyOf(reachabilityValues));

        EvidenceReference impact = reference(
                EvidenceDimension.BUSINESS_MISSION_IMPACT, "impact", 8);
        put(dimensions, values, EvidenceDimension.BUSINESS_MISSION_IMPACT,
                List.of(impact),
                List.of(new BusinessMissionImpactEvidenceValue(
                        impact,
                        "Payments",
                        "payments",
                        ImpactDimension.AVAILABILITY,
                        ImpactLevel.SEVERE,
                        ImpactMethod.BUSINESS_IMPACT_ANALYSIS,
                        "Payment processing outage blocks settlement"
                )));

        RbvmDecisionInputSnapshot snapshot = RbvmDecisionInputSnapshot.create(
                FINDING_ID,
                9,
                POLICY_SHA,
                EVALUATED_AT,
                dimensions
        );
        return new Fixture(snapshot, Map.copyOf(values));
    }

    private static void put(
            EnumMap<EvidenceDimension, DimensionInput> dimensions,
            EnumMap<EvidenceDimension, List<ResolvedEvidence>> values,
            EvidenceDimension dimension,
            List<EvidenceReference> references,
            List<? extends ResolvedEvidence> resolved
    ) {
        dimensions.put(
                dimension,
                new DimensionInput(dimension, DimensionState.PRESENT, references)
        );
        values.put(dimension, List.copyOf(resolved));
    }

    private static EvidenceReference reference(
            EvidenceDimension dimension,
            String seed,
            int shaSeed
    ) {
        UUID id = UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8));
        String hex = Integer.toHexString(shaSeed & 0x0f);
        return new EvidenceReference(
                dimension,
                id,
                hex.repeat(64),
                "source-" + dimension.name().toLowerCase(java.util.Locale.ROOT),
                EVALUATED_AT.minusSeconds(300)
        );
    }

    private static EnumMap<EvidenceDimension, List<ResolvedEvidence>> copy(
            Map<EvidenceDimension, List<ResolvedEvidence>> source
    ) {
        EnumMap<EvidenceDimension, List<ResolvedEvidence>> output =
                new EnumMap<>(EvidenceDimension.class);
        output.putAll(source);
        return output;
    }

    private static void assertRejected(Runnable action, String messagePart) {
        boolean rejected = false;
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            rejected = expected.getMessage().toLowerCase(java.util.Locale.ROOT)
                    .contains(messagePart.toLowerCase(java.util.Locale.ROOT));
        }
        assert rejected : "expected rejection containing: " + messagePart;
    }

    private record Fixture(
            RbvmDecisionInputSnapshot snapshot,
            Map<EvidenceDimension, List<ResolvedEvidence>> values
    ) {
    }
}
