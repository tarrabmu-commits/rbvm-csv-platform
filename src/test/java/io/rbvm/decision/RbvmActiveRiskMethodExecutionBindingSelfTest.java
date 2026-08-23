package io.rbvm.decision;

import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding.ResultFamily;

import java.time.Instant;
import java.util.Arrays;

public final class RbvmActiveRiskMethodExecutionBindingSelfTest {
    private static final String INPUT_SHA = "0".repeat(64);
    private static final String RESULT_SHA = "1".repeat(64);
    private static final String FORMULA_POLICY_SHA =
            "92303a4df7e0381f379a929359349158aba2f5dbe8dd7e51fc211abc8f2238cf";
    private static final String ACTIVATION_EVENT_SHA =
            "b8a4866b9e562332262bfebabf7a97543e27aa58dae4c60e87402a74d76b8043";
    private static final String BINDING_SHA =
            "72cb38f987d28316565dca9794fcd3f9b22b4f1e4b4c57272ebad22cb35a5760";

    private RbvmActiveRiskMethodExecutionBindingSelfTest() {
    }

    public static void main(String[] args) {
        formulaGoldenVectorIsStable();
        derivedPoliciesBindOnlyDerivedResults();
        clearedAndMismatchedPoliciesAreRejected();
        rehydrationDetectsIdentityTampering();
        System.out.println("RbvmActiveRiskMethodExecutionBindingSelfTest: PASS");
    }

    private static void formulaGoldenVectorIsStable() {
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        assert policy.policySha256().equals(FORMULA_POLICY_SHA);
        RbvmRiskMethodSelectionPolicyActivationEvent activation =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        7,
                        policy,
                        "execution-test",
                        "",
                        Instant.parse("2026-08-23T10:00:00Z")
                );
        assert activation.eventSha256().equals(ACTIVATION_EVENT_SHA);

        RbvmActiveRiskMethodExecutionBinding binding =
                RbvmActiveRiskMethodExecutionBinding.bind(
                        activation,
                        policy,
                        INPUT_SHA,
                        ResultFamily.RBVM_FORMULA_RESULT,
                        RESULT_SHA
                );

        assert binding.contractId().equals("RBVM_ACTIVE_RISK_METHOD_EXECUTION_BINDING_V1");
        assert binding.semantics().equals(
                "EXACT_ACTIVATION_EVENT_EXACT_POLICY_EXACT_PRIMARY_METHOD_EXACT_DECISION_INPUT_EXACT_RESULT"
        );
        assert binding.activationRevision() == 7;
        assert binding.activationEventSha256().equals(ACTIVATION_EVENT_SHA);
        assert binding.policyRevision() == 1;
        assert binding.policySha256().equals(FORMULA_POLICY_SHA);
        assert binding.selectionRole() == RbvmRiskMethodSelectionPolicy.SelectionRole.PRIMARY;
        assert binding.methodFamily() == RbvmRiskMethodSelectionPolicy.MethodFamily.RBVM_FORMULA;
        assert binding.methodId().equals(RbvmFormulaV1.FORMULA_ID);
        assert binding.methodVersion() == RbvmFormulaV1.FORMULA_VERSION;
        assert binding.methodSha256().equals(RbvmFormulaV1.FORMULA_SHA256);
        assert binding.inputSnapshotSha256().equals(INPUT_SHA);
        assert binding.resultFamily() == ResultFamily.RBVM_FORMULA_RESULT;
        assert binding.resultSha256().equals(RESULT_SHA);
        assert binding.canonicalPayload().length == 541;
        assert binding.bindingSha256().equals(BINDING_SHA);
        assert Arrays.equals(binding.canonicalPayload(), binding.canonicalPayload());
    }

    private static void derivedPoliciesBindOnlyDerivedResults() {
        for (RbvmDerivedRiskMethodology.Definition definition
                : RbvmDerivedRiskMethodologyCatalog.definitions()) {
            RbvmRiskMethodSelectionPolicy policy =
                    RbvmRiskMethodSelectionPolicy.derived(3, definition);
            RbvmRiskMethodSelectionPolicyActivationEvent activation =
                    RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                            9,
                            policy,
                            "execution-test",
                            "",
                            Instant.parse("2026-08-23T10:01:00Z")
                    );
            RbvmActiveRiskMethodExecutionBinding binding =
                    RbvmActiveRiskMethodExecutionBinding.bind(
                            activation,
                            policy,
                            "2".repeat(64),
                            ResultFamily.DERIVED_RISK_RESULT,
                            "3".repeat(64)
                    );
            assert binding.methodFamily()
                    == RbvmRiskMethodSelectionPolicy.MethodFamily.STANDARD_DERIVED;
            assert binding.methodId().equals(definition.methodologyId());
            assert binding.methodVersion() == definition.version();
            assert binding.methodSha256().equals(definition.methodologySha256());
            assert binding.resultFamily() == ResultFamily.DERIVED_RISK_RESULT;

            expectIllegalArgument(() -> RbvmActiveRiskMethodExecutionBinding.bind(
                    activation,
                    policy,
                    "2".repeat(64),
                    ResultFamily.RBVM_FORMULA_RESULT,
                    "3".repeat(64)
            ));
        }
    }

    private static void clearedAndMismatchedPoliciesAreRejected() {
        RbvmRiskMethodSelectionPolicy formula = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RbvmRiskMethodSelectionPolicy otherFormula = RbvmRiskMethodSelectionPolicy.formulaV1(2);
        RbvmRiskMethodSelectionPolicyActivationEvent cleared =
                RbvmRiskMethodSelectionPolicyActivationEvent.clear(
                        8,
                        "execution-test",
                        "",
                        Instant.parse("2026-08-23T10:02:00Z")
                );
        expectIllegalArgument(() -> RbvmActiveRiskMethodExecutionBinding.bind(
                cleared,
                formula,
                INPUT_SHA,
                ResultFamily.RBVM_FORMULA_RESULT,
                RESULT_SHA
        ));

        RbvmRiskMethodSelectionPolicyActivationEvent active =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        8,
                        formula,
                        "execution-test",
                        "",
                        Instant.parse("2026-08-23T10:02:01Z")
                );
        expectIllegalArgument(() -> RbvmActiveRiskMethodExecutionBinding.bind(
                active,
                otherFormula,
                INPUT_SHA,
                ResultFamily.RBVM_FORMULA_RESULT,
                RESULT_SHA
        ));
    }

    private static void rehydrationDetectsIdentityTampering() {
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RbvmRiskMethodSelectionPolicyActivationEvent activation =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        7,
                        policy,
                        "execution-test",
                        "",
                        Instant.parse("2026-08-23T10:00:00Z")
                );
        RbvmActiveRiskMethodExecutionBinding binding =
                RbvmActiveRiskMethodExecutionBinding.bind(
                        activation,
                        policy,
                        INPUT_SHA,
                        ResultFamily.RBVM_FORMULA_RESULT,
                        RESULT_SHA
                );

        RbvmActiveRiskMethodExecutionBinding replayed =
                RbvmActiveRiskMethodExecutionBinding.rehydrate(
                        binding.activationRevision(),
                        binding.activationEventSha256(),
                        binding.policyRevision(),
                        binding.policySha256(),
                        binding.selectionRole(),
                        binding.methodFamily(),
                        binding.methodId(),
                        binding.methodVersion(),
                        binding.methodSha256(),
                        binding.inputSnapshotSha256(),
                        binding.resultFamily(),
                        binding.resultSha256(),
                        binding.bindingSha256()
                );
        assert replayed.bindingSha256().equals(BINDING_SHA);

        expectIllegalArgument(() -> RbvmActiveRiskMethodExecutionBinding.rehydrate(
                binding.activationRevision(),
                binding.activationEventSha256(),
                binding.policyRevision(),
                binding.policySha256(),
                binding.selectionRole(),
                binding.methodFamily(),
                binding.methodId(),
                binding.methodVersion(),
                binding.methodSha256(),
                binding.inputSnapshotSha256(),
                binding.resultFamily(),
                "4".repeat(64),
                binding.bindingSha256()
        ));
    }

    private static void expectIllegalArgument(Runnable action) {
        boolean rejected = false;
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        assert rejected;
    }
}
