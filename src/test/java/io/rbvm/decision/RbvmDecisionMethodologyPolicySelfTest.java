package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;

import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.AmbiguityHandling.PRESERVE_AMBIGUOUS;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.FreshnessMode.MAX_AGE_SECONDS;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.FreshnessMode.NO_AGE_LIMIT;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.LegacyPriorityHandling.EXCLUDE_LEGACY_PRIORITY_TIER;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.MissingEvidenceHandling.PRESERVE_UNKNOWN;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.SourceSelectionMode.ALL_SOURCES;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.SourceSelectionMode.EXPLICIT_ALLOWLIST;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.SubjectScope.FINDING;

public final class RbvmDecisionMethodologyPolicySelfTest {
    private RbvmDecisionMethodologyPolicySelfTest() {
    }

    public static void main(String[] args) {
        acceptsCompleteFindingScopedSelectionPolicy();
        requiresEveryIndependentEvidenceDimension();
        validatesAllowlistAndFreshnessRules();
        canonicalHashIsVerifiableAndOrderIndependent();
        exposesNoDecisionFormulaFields();
        System.out.println("RbvmDecisionMethodologyPolicySelfTest: PASS");
    }

    private static void acceptsCompleteFindingScopedSelectionPolicy() {
        EnumMap<EvidenceDimension, RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy> policies =
                completePolicies();
        policies.put(
                EvidenceDimension.TECHNICAL_SEVERITY,
                new RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy(
                        EvidenceDimension.TECHNICAL_SEVERITY,
                        EXPLICIT_ALLOWLIST,
                        List.of("nvd-cvss-v31", "vendor-advisory"),
                        MAX_AGE_SECONDS,
                        2_592_000L
                )
        );

        RbvmDecisionMethodologyPolicy policy = createPolicy(1, policies);

        assert policy.contractId().equals("RBVM_DECISION_METHODOLOGY_V1");
        assert policy.semantics().equals("FINDING_SCOPED_EXPLICIT_EVIDENCE_SELECTION_POLICY");
        assert policy.subjectScope() == FINDING;
        assert policy.policySha256().matches("[a-f0-9]{64}");
        assert policy.canonicalPayload().length > 0;
        assert policy.evidencePolicies().keySet().equals(Set.of(EvidenceDimension.values()));
        assert policy.evidencePolicies().get(EvidenceDimension.TECHNICAL_SEVERITY)
                .sourceAllowlist().equals(List.of("nvd-cvss-v31", "vendor-advisory"));
        assert policy.evidencePolicies().get(EvidenceDimension.TECHNICAL_SEVERITY)
                .maximumAgeSeconds() == 2_592_000L;
    }

    private static void requiresEveryIndependentEvidenceDimension() {
        EnumMap<EvidenceDimension, RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy> policies =
                completePolicies();
        policies.remove(EvidenceDimension.BUSINESS_MISSION_IMPACT);
        assertRejected(() -> createPolicy(1, policies));
    }

    private static void validatesAllowlistAndFreshnessRules() {
        assertRejected(() -> new RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy(
                EvidenceDimension.APPLICABILITY,
                ALL_SOURCES,
                List.of("source-that-must-not-be-there"),
                NO_AGE_LIMIT,
                null
        ));
        assertRejected(() -> new RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy(
                EvidenceDimension.APPLICABILITY,
                EXPLICIT_ALLOWLIST,
                List.of(),
                NO_AGE_LIMIT,
                null
        ));
        assertRejected(() -> new RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy(
                EvidenceDimension.APPLICABILITY,
                ALL_SOURCES,
                List.of(),
                MAX_AGE_SECONDS,
                0L
        ));
        assertRejected(() -> new RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy(
                EvidenceDimension.APPLICABILITY,
                ALL_SOURCES,
                List.of(),
                NO_AGE_LIMIT,
                86_400L
        ));
        assertRejected(() -> new RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy(
                EvidenceDimension.APPLICABILITY,
                EXPLICIT_ALLOWLIST,
                List.of("same", "same"),
                NO_AGE_LIMIT,
                null
        ));
    }

    private static void canonicalHashIsVerifiableAndOrderIndependent() {
        EnumMap<EvidenceDimension, RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy> first =
                completePolicies();
        first.put(
                EvidenceDimension.KNOWN_EXPLOITATION,
                new RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy(
                        EvidenceDimension.KNOWN_EXPLOITATION,
                        EXPLICIT_ALLOWLIST,
                        List.of("source-b", "source-a"),
                        NO_AGE_LIMIT,
                        null
                )
        );
        RbvmDecisionMethodologyPolicy policy = createPolicy(7, first);
        assert policy.evidencePolicies().get(EvidenceDimension.KNOWN_EXPLOITATION)
                .sourceAllowlist().equals(List.of("source-a", "source-b"));

        EnumMap<EvidenceDimension, RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy> second =
                completePolicies();
        second.put(
                EvidenceDimension.KNOWN_EXPLOITATION,
                new RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy(
                        EvidenceDimension.KNOWN_EXPLOITATION,
                        EXPLICIT_ALLOWLIST,
                        List.of("source-a", "source-b"),
                        NO_AGE_LIMIT,
                        null
                )
        );
        RbvmDecisionMethodologyPolicy sameSemantics = createPolicy(7, second);
        assert policy.policySha256().equals(sameSemantics.policySha256());
        assert Arrays.equals(policy.canonicalPayload(), sameSemantics.canonicalPayload());

        assertRejected(() -> new RbvmDecisionMethodologyPolicy(
                RbvmDecisionMethodologyPolicy.ID,
                policy.revision(),
                "0".repeat(64),
                policy.subjectScope(),
                policy.missingEvidenceHandling(),
                policy.ambiguityHandling(),
                policy.legacyPriorityHandling(),
                policy.evidencePolicies()
        ));
    }

    private static void exposesNoDecisionFormulaFields() {
        Set<String> forbiddenTopLevelNames = Set.of(
                "riskscore", "prioritytier", "sladays", "impactweight", "aggregateimpactscore",
                "monetaryloss", "internetexposed", "attackpathscore"
        );
        Set<String> forbiddenSelectionTokens = Set.of(
                "weight", "score", "priority", "sla", "threshold", "multiplier", "coefficient",
                "lossamount", "monetaryloss", "internetexposed", "attackpath"
        );
        Set<String> components = componentNames(RbvmDecisionMethodologyPolicy.class);
        Set<String> selectionComponents = componentNames(
                RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy.class);
        for (String name : forbiddenTopLevelNames) {
            assert !components.contains(name) : name;
        }
        for (String token : forbiddenSelectionTokens) {
            assert selectionComponents.stream().noneMatch(name -> name.contains(token)) : token;
        }

        assert RbvmDecisionMethodologyPolicy.MissingEvidenceHandling.values().length == 1;
        assert RbvmDecisionMethodologyPolicy.MissingEvidenceHandling.values()[0] == PRESERVE_UNKNOWN;
        assert RbvmDecisionMethodologyPolicy.AmbiguityHandling.values().length == 1;
        assert RbvmDecisionMethodologyPolicy.AmbiguityHandling.values()[0] == PRESERVE_AMBIGUOUS;
        assert RbvmDecisionMethodologyPolicy.LegacyPriorityHandling.values().length == 1;
        assert RbvmDecisionMethodologyPolicy.LegacyPriorityHandling.values()[0]
                == EXCLUDE_LEGACY_PRIORITY_TIER;
    }

    private static RbvmDecisionMethodologyPolicy createPolicy(
            int revision,
            EnumMap<EvidenceDimension, RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy> policies
    ) {
        return RbvmDecisionMethodologyPolicy.create(
                revision,
                FINDING,
                PRESERVE_UNKNOWN,
                PRESERVE_AMBIGUOUS,
                EXCLUDE_LEGACY_PRIORITY_TIER,
                policies
        );
    }

    private static Set<String> componentNames(Class<?> type) {
        return java.util.Arrays.stream(type.getRecordComponents())
                .map(RecordComponent::getName)
                .map(name -> name.toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
    }

    private static EnumMap<EvidenceDimension, RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy>
            completePolicies() {
        EnumMap<EvidenceDimension, RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy> output =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            output.put(
                    dimension,
                    new RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy(
                            dimension,
                            ALL_SOURCES,
                            List.of(),
                            NO_AGE_LIMIT,
                            null
                    )
            );
        }
        return output;
    }

    private static void assertRejected(Runnable operation) {
        boolean rejected = false;
        try {
            operation.run();
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        assert rejected;
    }
}
