package io.rbvm.postgres;

import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding;
import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding.ResultFamily;
import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy.MethodFamily;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy.SelectionRole;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent.ActivationState;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;

public final class DefaultActiveRiskMethodExecutionBindingMaterializerSelfTest {
    private static final String INPUT_SHA = "0".repeat(64);

    private DefaultActiveRiskMethodExecutionBindingMaterializerSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        materializesFormulaOnceAndReplaysBindingWithoutReexecution();
        materializesEveryDerivedIdentityExactly();
        rejectsMissingWrongAndClearedActivations();
        rejectsPolicyAndNativeResultIntegrityFailures();
        rejectsUnavailableHistoricalSelectedMethod();
        rejectsExecutionBindingConflict();
        System.out.println("DefaultActiveRiskMethodExecutionBindingMaterializerSelfTest: PASS");
    }

    private static void materializesFormulaOnceAndReplaysBindingWithoutReexecution()
            throws Exception {
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RbvmRiskMethodSelectionPolicyActivationEvent activation = active(2, policy, "formula-test");
        MemoryPolicyStore policies = new MemoryPolicyStore(policy, activation, true);
        MemoryBindingStore bindings = new MemoryBindingStore();
        CountingResultMaterializer results = new CountingResultMaterializer("a".repeat(64));
        DefaultActiveRiskMethodExecutionBindingMaterializer materializer = materializer(
                policies,
                results,
                bindings
        );

        ActiveRiskMethodExecutionBindingMaterializationResult inserted = materializer.materialize(
                2,
                activation.eventSha256(),
                INPUT_SHA
        );
        assert inserted.installResult().status()
                == ActiveRiskMethodExecutionBindingInstallResult.Status.INSERTED;
        assert inserted.binding().methodFamily() == MethodFamily.RBVM_FORMULA;
        assert inserted.binding().methodId().equals(RbvmFormulaV1.FORMULA_ID);
        assert inserted.binding().methodVersion() == RbvmFormulaV1.FORMULA_VERSION;
        assert inserted.binding().methodSha256().equals(RbvmFormulaV1.FORMULA_SHA256);
        assert inserted.binding().resultFamily() == ResultFamily.RBVM_FORMULA_RESULT;
        assert inserted.binding().resultSha256().equals("a".repeat(64));
        assert results.calls == 1;

        ActiveRiskMethodExecutionBindingMaterializationResult replayed = materializer.materialize(
                2,
                activation.eventSha256(),
                INPUT_SHA
        );
        assert replayed.replayed();
        assert replayed.binding().bindingSha256().equals(inserted.binding().bindingSha256());
        assert results.calls == 1 : "existing binding replay must not re-execute the risk method";
    }

    private static void materializesEveryDerivedIdentityExactly() throws Exception {
        int revision = 10;
        for (RbvmDerivedRiskMethodology.Definition definition
                : RbvmDerivedRiskMethodologyCatalog.definitions()) {
            RbvmRiskMethodSelectionPolicy policy =
                    RbvmRiskMethodSelectionPolicy.derived(revision, definition);
            RbvmRiskMethodSelectionPolicyActivationEvent activation =
                    active(revision + 20, policy, "derived-test-" + revision);
            MemoryPolicyStore policies = new MemoryPolicyStore(policy, activation, true);
            MemoryBindingStore bindings = new MemoryBindingStore();
            CountingResultMaterializer results = new CountingResultMaterializer("b".repeat(64));

            RbvmActiveRiskMethodExecutionBinding binding = materializer(
                    policies,
                    results,
                    bindings
            ).materialize(
                    activation.activationRevision(),
                    activation.eventSha256(),
                    "1".repeat(64)
            ).binding();

            assert binding.methodFamily() == MethodFamily.STANDARD_DERIVED;
            assert binding.methodId().equals(definition.methodologyId());
            assert binding.methodVersion() == definition.version();
            assert binding.methodSha256().equals(definition.methodologySha256());
            assert binding.resultFamily() == ResultFamily.DERIVED_RISK_RESULT;
            assert binding.resultSha256().equals("b".repeat(64));
            assert results.calls == 1;
            revision++;
        }
    }

    private static void rejectsMissingWrongAndClearedActivations() throws Exception {
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RbvmRiskMethodSelectionPolicyActivationEvent activation = active(3, policy, "exact-test");
        CountingResultMaterializer results = new CountingResultMaterializer("c".repeat(64));
        DefaultActiveRiskMethodExecutionBindingMaterializer exact = materializer(
                new MemoryPolicyStore(policy, activation, true),
                results,
                new MemoryBindingStore()
        );

        expect(
                DefaultActiveRiskMethodExecutionBindingMaterializer.ActivationNotFoundException.class,
                () -> exact.materialize(3, "f".repeat(64), INPUT_SHA)
        );
        expect(
                DefaultActiveRiskMethodExecutionBindingMaterializer.ActivationNotFoundException.class,
                () -> exact.materialize(4, activation.eventSha256(), INPUT_SHA)
        );

        RbvmRiskMethodSelectionPolicyActivationEvent cleared =
                RbvmRiskMethodSelectionPolicyActivationEvent.clear(
                        4,
                        "clear-test",
                        "",
                        Instant.parse("2026-08-23T10:20:00Z")
                );
        DefaultActiveRiskMethodExecutionBindingMaterializer clearedMaterializer = materializer(
                new MemoryPolicyStore(policy, cleared, true),
                results,
                new MemoryBindingStore()
        );
        expect(
                DefaultActiveRiskMethodExecutionBindingMaterializer.ExplicitlyClearedActivationException.class,
                () -> clearedMaterializer.materialize(4, cleared.eventSha256(), INPUT_SHA)
        );

        DefaultActiveRiskMethodExecutionBindingMaterializer noV26 = materializer(
                new MemoryPolicyStore(policy, activation, false),
                results,
                new MemoryBindingStore()
        );
        expect(
                DefaultActiveRiskMethodExecutionBindingMaterializer.ActivationPersistenceUnavailableException.class,
                () -> noV26.materialize(3, activation.eventSha256(), INPUT_SHA)
        );
        assert results.calls == 0;
    }

    private static void rejectsPolicyAndNativeResultIntegrityFailures() throws Exception {
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RbvmRiskMethodSelectionPolicyActivationEvent activation = active(5, policy, "integrity-test");
        MemoryPolicyStore missingPolicy = new MemoryPolicyStore(null, activation, true);
        expect(
                DefaultActiveRiskMethodExecutionBindingMaterializer.PolicyIntegrityFailureException.class,
                () -> materializer(
                        missingPolicy,
                        new CountingResultMaterializer("d".repeat(64)),
                        new MemoryBindingStore()
                ).materialize(5, activation.eventSha256(), INPUT_SHA)
        );

        ActiveRiskMethodResultMaterializer mismatched = (selected, input) ->
                new ActiveRiskMethodNativeResult(
                        input,
                        selected.methodFamily(),
                        "WRONG_FORMULA_ID",
                        selected.methodVersion(),
                        selected.methodSha256(),
                        ResultFamily.RBVM_FORMULA_RESULT,
                        "e".repeat(64)
                );
        expect(
                DefaultActiveRiskMethodExecutionBindingMaterializer.ExecutionBindingIntegrityFailureException.class,
                () -> materializer(
                        new MemoryPolicyStore(policy, activation, true),
                        mismatched,
                        new MemoryBindingStore()
                ).materialize(5, activation.eventSha256(), INPUT_SHA)
        );
    }

    private static void rejectsUnavailableHistoricalSelectedMethod() throws Exception {
        String methodId = "REMOVED_DERIVED_METHOD_V1";
        String methodSha = "6".repeat(64);
        int policyRevision = 17;
        String policySha = historicalPolicySha(
                policyRevision,
                MethodFamily.STANDARD_DERIVED,
                methodId,
                1,
                methodSha
        );
        RbvmRiskMethodSelectionPolicy historical = RbvmRiskMethodSelectionPolicy.rehydrate(
                RbvmRiskMethodSelectionPolicy.ID,
                policyRevision,
                policySha,
                SelectionRole.PRIMARY,
                MethodFamily.STANDARD_DERIVED,
                methodId,
                1,
                methodSha
        );
        int activationRevision = 27;
        Instant recordedAt = Instant.parse("2026-08-23T10:30:00Z");
        String eventSha = historicalActivationSha(
                activationRevision,
                policyRevision,
                policySha,
                "historical-test",
                recordedAt
        );
        RbvmRiskMethodSelectionPolicyActivationEvent activation =
                RbvmRiskMethodSelectionPolicyActivationEvent.rehydrate(
                        activationRevision,
                        ActivationState.ACTIVE,
                        policyRevision,
                        policySha,
                        "historical-test",
                        "",
                        recordedAt,
                        eventSha
                );

        CountingResultMaterializer results = new CountingResultMaterializer("7".repeat(64));
        expect(
                DefaultActiveRiskMethodExecutionBindingMaterializer.SelectedMethodUnavailableException.class,
                () -> materializer(
                        new MemoryPolicyStore(historical, activation, true),
                        results,
                        new MemoryBindingStore()
                ).materialize(activationRevision, eventSha, INPUT_SHA)
        );
        assert results.calls == 0;
    }

    private static void rejectsExecutionBindingConflict() throws Exception {
        RbvmRiskMethodSelectionPolicy policy = RbvmRiskMethodSelectionPolicy.formulaV1(1);
        RbvmRiskMethodSelectionPolicyActivationEvent activation = active(6, policy, "conflict-test");
        MemoryBindingStore bindings = new MemoryBindingStore();
        bindings.forceConflict = true;
        expect(
                DefaultActiveRiskMethodExecutionBindingMaterializer.ExecutionBindingConflictException.class,
                () -> materializer(
                        new MemoryPolicyStore(policy, activation, true),
                        new CountingResultMaterializer("8".repeat(64)),
                        bindings
                ).materialize(6, activation.eventSha256(), INPUT_SHA)
        );
    }

    private static DefaultActiveRiskMethodExecutionBindingMaterializer materializer(
            RiskMethodSelectionPolicyStore policies,
            ActiveRiskMethodResultMaterializer results,
            ActiveRiskMethodExecutionBindingStore bindings
    ) {
        return new DefaultActiveRiskMethodExecutionBindingMaterializer(policies, results, bindings);
    }

    private static RbvmRiskMethodSelectionPolicyActivationEvent active(
            int activationRevision,
            RbvmRiskMethodSelectionPolicy policy,
            String actor
    ) {
        return RbvmRiskMethodSelectionPolicyActivationEvent.activate(
                activationRevision,
                policy,
                actor,
                "",
                Instant.parse("2026-08-23T10:10:00Z").plusSeconds(activationRevision)
        );
    }

    private static String historicalPolicySha(
            int revision,
            MethodFamily family,
            String methodId,
            int methodVersion,
            String methodSha
    ) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            writeText(output, RbvmRiskMethodSelectionPolicy.ID);
            output.writeInt(revision);
            writeText(output, RbvmRiskMethodSelectionPolicy.SEMANTICS);
            writeText(output, SelectionRole.PRIMARY.name());
            writeText(output, family.name());
            writeText(output, methodId);
            output.writeInt(methodVersion);
            writeText(output, methodSha);
        }
        return sha256(bytes.toByteArray());
    }

    private static String historicalActivationSha(
            int activationRevision,
            int policyRevision,
            String policySha,
            String actor,
            Instant recordedAt
    ) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeUTF(RbvmRiskMethodSelectionPolicyActivationEvent.ID);
            output.writeUTF(RbvmRiskMethodSelectionPolicyActivationEvent.SEMANTICS);
            output.writeInt(activationRevision);
            output.writeUTF(ActivationState.ACTIVE.name());
            output.writeBoolean(true);
            output.writeInt(policyRevision);
            output.writeUTF(policySha);
            output.writeUTF(actor);
            output.writeUTF("");
            output.writeLong(recordedAt.getEpochSecond());
            output.writeInt(recordedAt.getNano());
        }
        return sha256(bytes.toByteArray());
    }

    private static void writeText(DataOutputStream output, String value) throws Exception {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void expect(Class<? extends Throwable> type, ThrowingAction action)
            throws Exception {
        boolean rejected = false;
        try {
            action.run();
        } catch (Throwable failure) {
            if (!type.isInstance(failure)) throw failure;
            rejected = true;
        }
        assert rejected : "expected " + type.getSimpleName();
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }

    private static final class CountingResultMaterializer
            implements ActiveRiskMethodResultMaterializer {
        private final String resultSha;
        private int calls;

        private CountingResultMaterializer(String resultSha) {
            this.resultSha = resultSha;
        }

        @Override
        public ActiveRiskMethodNativeResult materialize(
                RbvmRiskMethodSelectionPolicy policy,
                String inputSnapshotSha256
        ) {
            calls++;
            return new ActiveRiskMethodNativeResult(
                    inputSnapshotSha256,
                    policy.methodFamily(),
                    policy.methodId(),
                    policy.methodVersion(),
                    policy.methodSha256(),
                    policy.methodFamily() == MethodFamily.RBVM_FORMULA
                            ? ResultFamily.RBVM_FORMULA_RESULT
                            : ResultFamily.DERIVED_RISK_RESULT,
                    resultSha
            );
        }
    }

    private static final class MemoryPolicyStore implements RiskMethodSelectionPolicyStore {
        private final RbvmRiskMethodSelectionPolicy policy;
        private final RiskMethodSelectionPolicyActivationEvent activation;
        private final boolean activationEnabled;

        private MemoryPolicyStore(
                RbvmRiskMethodSelectionPolicy policy,
                RbvmRiskMethodSelectionPolicyActivationEvent activation,
                boolean activationEnabled
        ) {
            this.policy = policy;
            this.activation = new RiskMethodSelectionPolicyActivationEvent(activation);
            this.activationEnabled = activationEnabled;
        }

        @Override
        public RiskMethodSelectionPolicyInstallResult install(RbvmRiskMethodSelectionPolicy ignored) {
            throw new UnsupportedOperationException("read-only test store");
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByRevision(int revision) {
            return policy != null && policy.revision() == revision
                    ? Optional.of(policy)
                    : Optional.empty();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByPolicySha256(String policySha256) {
            return policy != null && policy.policySha256().equals(policySha256)
                    ? Optional.of(policy)
                    : Optional.empty();
        }

        @Override
        public Optional<RiskMethodSelectionPolicyActivationStore> activationStore() {
            return activationEnabled ? Optional.of(activation) : Optional.empty();
        }
    }

    private static final class RiskMethodSelectionPolicyActivationEvent
            implements RiskMethodSelectionPolicyActivationStore {
        private final RbvmRiskMethodSelectionPolicyActivationEvent event;

        private RiskMethodSelectionPolicyActivationEvent(
                RbvmRiskMethodSelectionPolicyActivationEvent event
        ) {
            this.event = event;
        }

        @Override
        public RiskMethodSelectionPolicyActivationInstallResult install(
                RbvmRiskMethodSelectionPolicyActivationEvent ignored
        ) {
            throw new UnsupportedOperationException("read-only test store");
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByActivationRevision(
                int activationRevision
        ) {
            return event.activationRevision() == activationRevision
                    ? Optional.of(event)
                    : Optional.empty();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByEventSha256(
                String eventSha256
        ) {
            return event.eventSha256().equals(eventSha256) ? Optional.of(event) : Optional.empty();
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> current() {
            throw new AssertionError("execution binding materializer must never query current activation");
        }
    }

    private static final class MemoryBindingStore implements ActiveRiskMethodExecutionBindingStore {
        private final Map<String, RbvmActiveRiskMethodExecutionBinding> byExecution = new HashMap<>();
        private final Map<String, RbvmActiveRiskMethodExecutionBinding> bySha = new HashMap<>();
        private boolean forceConflict;

        @Override
        public ActiveRiskMethodExecutionBindingInstallResult install(
                RbvmActiveRiskMethodExecutionBinding binding
        ) {
            String key = binding.activationEventSha256() + ":" + binding.inputSnapshotSha256();
            RbvmActiveRiskMethodExecutionBinding existing = byExecution.get(key);
            if (forceConflict) {
                return new ActiveRiskMethodExecutionBindingInstallResult(
                        ActiveRiskMethodExecutionBindingInstallResult.Status.EXECUTION_CONFLICT,
                        binding.bindingSha256(),
                        "9".repeat(64)
                );
            }
            if (existing != null) {
                var status = existing.bindingSha256().equals(binding.bindingSha256())
                        ? ActiveRiskMethodExecutionBindingInstallResult.Status.REPLAYED
                        : ActiveRiskMethodExecutionBindingInstallResult.Status.EXECUTION_CONFLICT;
                return new ActiveRiskMethodExecutionBindingInstallResult(
                        status,
                        binding.bindingSha256(),
                        existing.bindingSha256()
                );
            }
            byExecution.put(key, binding);
            bySha.put(binding.bindingSha256(), binding);
            return new ActiveRiskMethodExecutionBindingInstallResult(
                    ActiveRiskMethodExecutionBindingInstallResult.Status.INSERTED,
                    binding.bindingSha256(),
                    binding.bindingSha256()
            );
        }

        @Override
        public Optional<RbvmActiveRiskMethodExecutionBinding> findByBindingSha256(
                String bindingSha256
        ) {
            return Optional.ofNullable(bySha.get(bindingSha256));
        }

        @Override
        public Optional<RbvmActiveRiskMethodExecutionBinding> findByActivationAndInput(
                String activationEventSha256,
                String inputSnapshotSha256
        ) {
            return Optional.ofNullable(byExecution.get(
                    activationEventSha256 + ":" + inputSnapshotSha256
            ));
        }
    }
}
