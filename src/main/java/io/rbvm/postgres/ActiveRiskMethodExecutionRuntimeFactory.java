package io.rbvm.postgres;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Discovers exact active-risk-method execution capabilities from PostgreSQL V27+. */
public final class ActiveRiskMethodExecutionRuntimeFactory {
    private static final int REQUIRED_SCHEMA_VERSION = 27;

    private ActiveRiskMethodExecutionRuntimeFactory() {
    }

    public static Optional<Runtime> fromEnvironment(Map<String, String> environment)
            throws IOException {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) return Optional.empty();

        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        PostgresMigrator migrator = new PostgresMigrator(connections);
        int installedVersion = settings.migrate() ? migrator.migrate() : migrator.installedVersion();
        if (installedVersion < REQUIRED_SCHEMA_VERSION) return Optional.empty();

        FormulaResultRuntimeFactory.Runtime formula = FormulaResultRuntimeFactory
                .fromEnvironment(environment)
                .orElseThrow(() -> new IOException(
                        "Formula result runtime is unavailable despite PostgreSQL V27 execution runtime"
                ));
        DerivedRiskResultRuntimeFactory.Runtime derived = DerivedRiskResultRuntimeFactory
                .fromEnvironment(environment)
                .orElseThrow(() -> new IOException(
                        "Derived risk runtime is unavailable despite PostgreSQL V27 execution runtime"
                ));

        RiskMethodSelectionPolicyStore policies =
                new PostgresRiskMethodSelectionPolicyStore(connections, false);
        RiskMethodSelectionPolicyActivationStore activations =
                new PostgresRiskMethodSelectionPolicyActivationStore(connections, false);
        ActiveRiskMethodExecutionBindingStore bindings =
                new PostgresActiveRiskMethodExecutionBindingStore(connections, false);
        ActiveRiskMethodResultMaterializer nativeResults =
                new DefaultActiveRiskMethodResultMaterializer(
                        formula.materializer(),
                        derived.materializer()
                );
        DefaultActiveRiskMethodExecutionBindingMaterializer materializer =
                new DefaultActiveRiskMethodExecutionBindingMaterializer(
                        policies,
                        activations,
                        nativeResults,
                        bindings
                );
        return Optional.of(new Runtime(bindings, materializer));
    }

    public record Runtime(
            ActiveRiskMethodExecutionBindingStore bindings,
            DefaultActiveRiskMethodExecutionBindingMaterializer materializer
    ) {
        public Runtime {
            bindings = Objects.requireNonNull(bindings, "bindings");
            materializer = Objects.requireNonNull(materializer, "materializer");
        }
    }
}
