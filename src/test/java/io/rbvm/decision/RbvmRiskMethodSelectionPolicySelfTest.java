package io.rbvm.decision;

import java.util.Arrays;

public final class RbvmRiskMethodSelectionPolicySelfTest {
    private static final String FORMULA_REVISION_1_POLICY_SHA256 =
            "92303a4df7e0381f379a929359349158aba2f5dbe8dd7e51fc211abc8f2238cf";

    private RbvmRiskMethodSelectionPolicySelfTest() {
    }

    public static void main(String[] args) {
        formulaIdentityIsFrozenAndCanonical();
        derivedMethodologiesRemainIndependentExactChoices();
        revisionChangesCanonicalIdentityWithoutChangingMethodIdentity();
        rehydrateRejectsCanonicalTampering();
        System.out.println("RbvmRiskMethodSelectionPolicySelfTest: PASS");
    }

    private static void formulaIdentityIsFrozenAndCanonical() {
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        assert policy.contractId().equals(RbvmRiskMethodSelectionPolicy.ID);
        assert policy.semantics().equals(RbvmRiskMethodSelectionPolicy.SEMANTICS);
        assert policy.selectionRole() == RbvmRiskMethodSelectionPolicy.SelectionRole.PRIMARY;
        assert policy.methodFamily() == RbvmRiskMethodSelectionPolicy.MethodFamily.RBVM_FORMULA;
        assert policy.methodId().equals(RbvmFormulaV1.FORMULA_ID);
        assert policy.methodVersion() == RbvmFormulaV1.FORMULA_VERSION;
        assert policy.methodSha256().equals(RbvmFormulaV1.FORMULA_SHA256);
        assert policy.canonicalPayload().length == 223;
        assert policy.policySha256().equals(FORMULA_REVISION_1_POLICY_SHA256);
        policy.requireCatalogBound();
    }

    private static void derivedMethodologiesRemainIndependentExactChoices() {
        int revision = 1;
        for (RbvmDerivedRiskMethodology.Definition definition
                : RbvmDerivedRiskMethodologyCatalog.definitions()) {
            RbvmRiskMethodSelectionPolicy policy =
                    RbvmRiskMethodSelectionPolicy.derived(revision++, definition);
            assert policy.methodFamily()
                    == RbvmRiskMethodSelectionPolicy.MethodFamily.STANDARD_DERIVED;
            assert policy.methodId().equals(definition.methodologyId());
            assert policy.methodVersion() == definition.version();
            assert policy.methodSha256().equals(definition.methodologySha256());
            policy.requireCatalogBound();
        }
    }

    private static void revisionChangesCanonicalIdentityWithoutChangingMethodIdentity() {
        RbvmRiskMethodSelectionPolicy first = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RbvmRiskMethodSelectionPolicy second = RbvmRiskMethodSelectionPolicy.formulaV1(2);
        assert first.methodId().equals(second.methodId());
        assert first.methodSha256().equals(second.methodSha256());
        assert !first.policySha256().equals(second.policySha256());
        assert !Arrays.equals(first.canonicalPayload(), second.canonicalPayload());
    }

    private static void rehydrateRejectsCanonicalTampering() {
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        boolean rejected = false;
        try {
            RbvmRiskMethodSelectionPolicy.rehydrate(
                    policy.contractId(),
                    policy.revision(),
                    "0".repeat(64),
                    policy.selectionRole(),
                    policy.methodFamily(),
                    policy.methodId(),
                    policy.methodVersion(),
                    policy.methodSha256()
            );
        } catch (IllegalArgumentException expected) {
            rejected = expected.getMessage().contains("policySha256");
        }
        assert rejected;
    }
}
