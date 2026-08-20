package io.rbvm.postgres;

import io.rbvm.csv.NoopCanonicalProjection;
import io.rbvm.decision.DecisionInputEvidenceResolver;
import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy;
import io.rbvm.domain.InMemoryDomainCatalog;

import java.util.Map;
import java.util.Optional;

public final class DecisionRuntimeFactorySelfTest {
    private DecisionRuntimeFactorySelfTest() {
    }

    public static void main(String[] args) throws Exception {
        disabledBackendDoesNotExposeDecisionRuntime();
        v15CompatibilityConstructorDefaultsDecisionRuntimeToEmpty();
        legacyDecisionRuntimeConstructorDefaultsResolverToEmpty();
        canonicalDecisionRuntimePreservesResolver();
        System.out.println("DecisionRuntimeFactorySelfTest: PASS");
    }

    private static void disabledBackendDoesNotExposeDecisionRuntime() throws Exception {
        CanonicalProjectionFactory.RuntimeComponents runtime =
                CanonicalProjectionFactory.runtimeFromEnvironment(Map.of());
        assert runtime.decisionRuntime().isEmpty();
        assert runtime.managedAssetRegistry().isEmpty();
    }

    private static void v15CompatibilityConstructorDefaultsDecisionRuntimeToEmpty() {
        CanonicalProjectionFactory.RuntimeComponents runtime =
                new CanonicalProjectionFactory.RuntimeComponents(
                        new NoopCanonicalProjection(),
                        new InMemoryDomainCatalog(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty()
                );
        assert runtime.decisionRuntime().isEmpty();
        assert runtime.managedAssetRegistry().isEmpty();
    }

    private static void legacyDecisionRuntimeConstructorDefaultsResolverToEmpty() {
        CanonicalProjectionFactory.DecisionRuntime runtime =
                new CanonicalProjectionFactory.DecisionRuntime(
                        policyStore(),
                        snapshotStore(),
                        materializer()
                );
        assert runtime.evidenceResolver().isEmpty();
    }

    private static void canonicalDecisionRuntimePreservesResolver() {
        DecisionInputEvidenceResolver resolver = snapshot -> {
            throw new AssertionError("resolver must not be invoked by factory wiring self-test");
        };
        CanonicalProjectionFactory.DecisionRuntime runtime =
                new CanonicalProjectionFactory.DecisionRuntime(
                        policyStore(),
                        snapshotStore(),
                        materializer(),
                        Optional.of(resolver)
                );
        assert runtime.evidenceResolver().orElseThrow() == resolver;
    }

    private static DecisionMethodologyPolicyStore policyStore() {
        return new DecisionMethodologyPolicyStore() {
            @Override
            public DecisionMethodologyPolicyInstallResult install(
                    RbvmDecisionMethodologyPolicy policy
            ) {
                throw new UnsupportedOperationException("unused test policy store");
            }

            @Override
            public Optional<RbvmDecisionMethodologyPolicy> findByRevision(int revision) {
                return Optional.empty();
            }
        };
    }

    private static DecisionInputSnapshotStore snapshotStore() {
        return new DecisionInputSnapshotStore() {
            @Override
            public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot snapshot) {
                throw new UnsupportedOperationException("unused test snapshot store");
            }

            @Override
            public Optional<RbvmDecisionInputSnapshot> findBySha256(String snapshotSha256) {
                return Optional.empty();
            }
        };
    }

    private static DecisionInputSnapshotMaterializer materializer() {
        return (findingId, revision, policySha, evaluatedAt) -> {
            throw new UnsupportedOperationException("unused test materializer");
        };
    }
}
