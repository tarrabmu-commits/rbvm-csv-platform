package io.rbvm.decision;

import java.time.Instant;
import java.util.Arrays;

public final class RbvmRiskMethodSelectionPolicyActivationEventSelfTest {
    private static final Instant RECORDED_AT = Instant.parse("2026-08-23T04:15:00Z");
    private static final String FROZEN_EVENT_SHA =
            "e7e1a60b1139e4ae98050516fce253998ca2ad1cc2a4c1113caf11a0f40b482b";

    private RbvmRiskMethodSelectionPolicyActivationEventSelfTest() {
    }

    public static void main(String[] args) {
        freezesCanonicalActiveIdentity();
        distinguishesActivationRevisionFromPolicyRevision();
        supportsExplicitClearedState();
        rejectsInvalidStateShapeAndTampering();
        System.out.println("RbvmRiskMethodSelectionPolicyActivationEventSelfTest: PASS");
    }

    private static void freezesCanonicalActiveIdentity() {
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RbvmRiskMethodSelectionPolicyActivationEvent event =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        1,
                        policy,
                        "operator-1",
                        "activate formula v1",
                        RECORDED_AT
                );
        assert event.contractId().equals(
                "RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_EVENT_V1");
        assert event.semantics().equals(
                "TENANT_SCOPED_EXPLICIT_ACTIVE_POLICY_POINTER_APPEND_ONLY");
        assert event.activationState()
                == RbvmRiskMethodSelectionPolicyActivationEvent.ActivationState.ACTIVE;
        assert event.activationRevision() == 1;
        assert event.policyRevision() == 1;
        assert event.policySha256().equals(policy.policySha256());
        assert event.canonicalPayload().length == 241 : event.canonicalPayload().length;
        assert event.eventSha256().equals(FROZEN_EVENT_SHA) : event.eventSha256();

        RbvmRiskMethodSelectionPolicyActivationEvent replay =
                RbvmRiskMethodSelectionPolicyActivationEvent.rehydrate(
                        event.activationRevision(),
                        event.activationState(),
                        event.policyRevision(),
                        event.policySha256(),
                        event.changedBy(),
                        event.changeNote(),
                        event.recordedAt(),
                        event.eventSha256()
                );
        assert replay.eventSha256().equals(event.eventSha256());
        assert Arrays.equals(replay.canonicalPayload(), event.canonicalPayload());
    }

    private static void distinguishesActivationRevisionFromPolicyRevision() {
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(7);
        RbvmRiskMethodSelectionPolicyActivationEvent event =
                RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                        3,
                        policy,
                        "operator-2",
                        "activate policy revision seven",
                        RECORDED_AT.plusSeconds(60)
                );
        assert event.activationRevision() == 3;
        assert event.policyRevision() == 7;
    }

    private static void supportsExplicitClearedState() {
        RbvmRiskMethodSelectionPolicyActivationEvent event =
                RbvmRiskMethodSelectionPolicyActivationEvent.clear(
                        4,
                        "operator-3",
                        "clear active risk method policy",
                        RECORDED_AT.plusSeconds(120)
                );
        assert event.activationState()
                == RbvmRiskMethodSelectionPolicyActivationEvent.ActivationState.CLEARED;
        assert event.policyRevision() == null;
        assert event.policySha256() == null;
        assert !event.activatesPolicy();
    }

    private static void rejectsInvalidStateShapeAndTampering() {
        assertRejected(() -> RbvmRiskMethodSelectionPolicyActivationEvent.rehydrate(
                1,
                RbvmRiskMethodSelectionPolicyActivationEvent.ActivationState.ACTIVE,
                null,
                null,
                "operator",
                "invalid",
                RECORDED_AT,
                "a".repeat(64)
        ));
        assertRejected(() -> RbvmRiskMethodSelectionPolicyActivationEvent.rehydrate(
                1,
                RbvmRiskMethodSelectionPolicyActivationEvent.ActivationState.CLEARED,
                1,
                "a".repeat(64),
                "operator",
                "invalid",
                RECORDED_AT,
                "b".repeat(64)
        ));
        assertRejected(() -> RbvmRiskMethodSelectionPolicyActivationEvent.rehydrate(
                1,
                RbvmRiskMethodSelectionPolicyActivationEvent.ActivationState.ACTIVE,
                1,
                RbvmRiskMethodSelectionPolicy.formulaV1(1).policySha256(),
                "operator-1",
                "activate formula v1",
                RECORDED_AT,
                "0".repeat(64)
        ));
    }

    private static void assertRejected(Runnable action) {
        boolean rejected = false;
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        assert rejected;
    }
}
