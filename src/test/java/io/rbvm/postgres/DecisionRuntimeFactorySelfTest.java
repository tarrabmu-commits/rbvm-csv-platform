package io.rbvm.postgres;

import io.rbvm.csv.NoopCanonicalProjection;
import io.rbvm.domain.InMemoryDomainCatalog;

import java.util.Map;
import java.util.Optional;

public final class DecisionRuntimeFactorySelfTest {
    private DecisionRuntimeFactorySelfTest() {
    }

    public static void main(String[] args) throws Exception {
        disabledBackendDoesNotExposeDecisionRuntime();
        v15CompatibilityConstructorDefaultsDecisionRuntimeToEmpty();
        System.out.println("DecisionRuntimeFactorySelfTest: PASS");
    }

    private static void disabledBackendDoesNotExposeDecisionRuntime() throws Exception {
        CanonicalProjectionFactory.RuntimeComponents runtime =
                CanonicalProjectionFactory.runtimeFromEnvironment(Map.of());
        assert runtime.decisionRuntime().isEmpty();
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
    }
}
