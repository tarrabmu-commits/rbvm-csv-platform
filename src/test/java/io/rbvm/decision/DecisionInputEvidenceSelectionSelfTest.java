package io.rbvm.decision;

import io.rbvm.decision.DecisionInputEvidenceSelection.Candidate;
import io.rbvm.decision.DecisionInputEvidenceSelection.Selection;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.FreshnessMode;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.SourceSelectionMode;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class DecisionInputEvidenceSelectionSelfTest {
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-19T18:00:00Z");

    private DecisionInputEvidenceSelectionSelfTest() {
    }

    public static void main(String[] args) {
        selectsLatestPerSourceAndIgnoresFutureRows();
        preservesIndependentSubgrainsWithoutInventingAmbiguity();
        marksCompetingSourcesWithinOneSubgrainAmbiguous();
        marksSameSourceLatestTimestampTieAmbiguous();
        appliesExplicitAllowlistBeforeAmbiguity();
        marksSelectedEvidenceStaleByPolicyAge();
        ambiguityTakesStatePrecedenceOverStaleness();
        preservesMissingWhenNothingAdmissibleExists();
        rejectsCrossDimensionCandidates();
        System.out.println("DecisionInputEvidenceSelectionSelfTest: PASS");
    }

    private static void selectsLatestPerSourceAndIgnoresFutureRows() {
        EvidenceSelectionPolicy policy = allSources(
                EvidenceDimension.TECHNICAL_SEVERITY,
                FreshnessMode.NO_AGE_LIMIT,
                null
        );
        Candidate old = candidate(policy.dimension(), "cve", "source-a", -7200, 1);
        Candidate latest = candidate(policy.dimension(), "cve", "source-a", -60, 2);
        Candidate future = candidate(policy.dimension(), "cve", "source-a", 60, 3);

        Selection selected = DecisionInputEvidenceSelection.select(
                policy, EVALUATED_AT, List.of(old, latest, future));
        assert selected.state() == DimensionState.PRESENT;
        assert selected.evidenceReferences().size() == 1;
        assert selected.evidenceReferences().get(0).evidenceId().equals(latest.evidenceId());
        assert !selected.hasAmbiguousSubgrain();
        assert !selected.hasStaleReference();
    }

    private static void preservesIndependentSubgrainsWithoutInventingAmbiguity() {
        EvidenceSelectionPolicy policy = allSources(
                EvidenceDimension.NETWORK_REACHABILITY,
                FreshnessMode.NO_AGE_LIMIT,
                null
        );
        Candidate endpoint443 = candidate(policy.dimension(), "internet|tcp|443", "scanner-a", -30, 1);
        Candidate endpoint22 = candidate(policy.dimension(), "internet|tcp|22", "scanner-a", -30, 2);

        Selection selected = DecisionInputEvidenceSelection.select(
                policy, EVALUATED_AT, List.of(endpoint443, endpoint22));
        assert selected.state() == DimensionState.PRESENT;
        assert selected.evidenceReferences().size() == 2;
        assert selected.subgrainReferenceCounts().size() == 2;
        assert selected.subgrainReferenceCounts().values().stream().allMatch(count -> count == 1);
        assert !selected.hasAmbiguousSubgrain();
    }

    private static void marksCompetingSourcesWithinOneSubgrainAmbiguous() {
        EvidenceSelectionPolicy policy = allSources(
                EvidenceDimension.ASSET_CONTEXT,
                FreshnessMode.NO_AGE_LIMIT,
                null
        );
        Candidate cmdb = candidate(policy.dimension(), "asset", "cmdb", -300, 1);
        Candidate serviceCatalog = candidate(policy.dimension(), "asset", "service-catalog", -200, 2);

        Selection selected = DecisionInputEvidenceSelection.select(
                policy, EVALUATED_AT, List.of(cmdb, serviceCatalog));
        assert selected.state() == DimensionState.AMBIGUOUS;
        assert selected.evidenceReferences().size() == 2;
        assert selected.subgrainReferenceCounts().get("asset") == 2;
        assert selected.hasAmbiguousSubgrain();
    }

    private static void marksSameSourceLatestTimestampTieAmbiguous() {
        EvidenceSelectionPolicy policy = allSources(
                EvidenceDimension.KNOWN_EXPLOITATION,
                FreshnessMode.NO_AGE_LIMIT,
                null
        );
        Candidate one = candidate(policy.dimension(), "cve", "kev-source", -60, 1);
        Candidate two = candidate(policy.dimension(), "cve", "kev-source", -60, 2);

        Selection selected = DecisionInputEvidenceSelection.select(
                policy, EVALUATED_AT, List.of(one, two));
        assert selected.state() == DimensionState.AMBIGUOUS;
        assert selected.evidenceReferences().size() == 2;
    }

    private static void appliesExplicitAllowlistBeforeAmbiguity() {
        EvidenceSelectionPolicy policy = new EvidenceSelectionPolicy(
                EvidenceDimension.EXPLOITATION_PROBABILITY,
                SourceSelectionMode.EXPLICIT_ALLOWLIST,
                List.of("first-epss"),
                FreshnessMode.NO_AGE_LIMIT,
                null
        );
        Candidate allowed = candidate(policy.dimension(), "cve", "first-epss", -30, 1);
        Candidate denied = candidate(policy.dimension(), "cve", "other-epss", -10, 2);

        Selection selected = DecisionInputEvidenceSelection.select(
                policy, EVALUATED_AT, List.of(allowed, denied));
        assert selected.state() == DimensionState.PRESENT;
        assert selected.evidenceReferences().size() == 1;
        assert selected.evidenceReferences().get(0).evidenceSource().equals("first-epss");
    }

    private static void marksSelectedEvidenceStaleByPolicyAge() {
        EvidenceSelectionPolicy policy = allSources(
                EvidenceDimension.BUSINESS_MISSION_IMPACT,
                FreshnessMode.MAX_AGE_SECONDS,
                3600L
        );
        Candidate fresh = candidate(policy.dimension(), "payments|availability", "bia", -1200, 1);
        Candidate stale = candidate(policy.dimension(), "payments|integrity", "bia", -7200, 2);

        Selection selected = DecisionInputEvidenceSelection.select(
                policy, EVALUATED_AT, List.of(fresh, stale));
        assert selected.state() == DimensionState.STALE;
        assert selected.evidenceReferences().size() == 2;
        assert selected.hasStaleReference();
        assert !selected.hasAmbiguousSubgrain();
    }

    private static void ambiguityTakesStatePrecedenceOverStaleness() {
        EvidenceSelectionPolicy policy = allSources(
                EvidenceDimension.NETWORK_REACHABILITY,
                FreshnessMode.MAX_AGE_SECONDS,
                3600L
        );
        Candidate staleA = candidate(policy.dimension(), "internet|tcp|443", "probe-a", -7200, 1);
        Candidate freshB = candidate(policy.dimension(), "internet|tcp|443", "probe-b", -60, 2);

        Selection selected = DecisionInputEvidenceSelection.select(
                policy, EVALUATED_AT, List.of(staleA, freshB));
        assert selected.state() == DimensionState.AMBIGUOUS;
        assert selected.hasAmbiguousSubgrain();
        assert selected.hasStaleReference();
    }

    private static void preservesMissingWhenNothingAdmissibleExists() {
        EvidenceSelectionPolicy policy = new EvidenceSelectionPolicy(
                EvidenceDimension.APPLICABILITY,
                SourceSelectionMode.EXPLICIT_ALLOWLIST,
                List.of("approved-source"),
                FreshnessMode.NO_AGE_LIMIT,
                null
        );
        Candidate denied = candidate(policy.dimension(), "finding", "other-source", -60, 1);
        Candidate future = candidate(policy.dimension(), "finding", "approved-source", 60, 2);

        Selection selected = DecisionInputEvidenceSelection.select(
                policy, EVALUATED_AT, List.of(denied, future));
        assert selected.state() == DimensionState.MISSING;
        assert selected.evidenceReferences().isEmpty();
        assert selected.subgrainReferenceCounts().isEmpty();
    }

    private static void rejectsCrossDimensionCandidates() {
        EvidenceSelectionPolicy policy = allSources(
                EvidenceDimension.ASSET_CONTEXT,
                FreshnessMode.NO_AGE_LIMIT,
                null
        );
        boolean rejected = false;
        try {
            DecisionInputEvidenceSelection.select(
                    policy,
                    EVALUATED_AT,
                    List.of(candidate(
                            EvidenceDimension.TECHNICAL_SEVERITY,
                            "asset",
                            "source",
                            -1,
                            1
                    ))
            );
        } catch (IllegalArgumentException expected) {
            rejected = expected.getMessage().contains("dimension");
        }
        assert rejected;
    }

    private static EvidenceSelectionPolicy allSources(
            EvidenceDimension dimension,
            FreshnessMode freshnessMode,
            Long maximumAgeSeconds
    ) {
        return new EvidenceSelectionPolicy(
                dimension,
                SourceSelectionMode.ALL_SOURCES,
                List.of(),
                freshnessMode,
                maximumAgeSeconds
        );
    }

    private static Candidate candidate(
            EvidenceDimension dimension,
            String subgrain,
            String source,
            long secondsFromEvaluation,
            int idSeed
    ) {
        return new Candidate(
                dimension,
                subgrain,
                UUID.nameUUIDFromBytes((dimension + "|" + source + "|" + idSeed)
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                Integer.toHexString(idSeed).substring(0, 1).repeat(64),
                source,
                EVALUATED_AT.plusSeconds(secondsFromEvaluation)
        );
    }
}
