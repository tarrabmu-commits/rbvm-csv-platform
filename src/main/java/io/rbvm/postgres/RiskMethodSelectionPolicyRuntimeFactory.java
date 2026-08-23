package io.rbvm.postgres;

import io.rbvm.decision.RbvmRiskMethodSelectionPolicy;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Discovers exact risk-method selection policy capabilities from PostgreSQL V25+. */
public final class RiskMethodSelectionPolicyRuntimeFactory {
    private static final int REQUIRED_SCHEMA_VERSION = 25;
    private static final int ACTIVATION_SCHEMA_VERSION = 26;

    private RiskMethodSelectionPolicyRuntimeFactory() {
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

        RiskMethodSelectionPolicyStore policies =
                new PostgresRiskMethodSelectionPolicyStore(connections, false);
        if (installedVersion >= ACTIVATION_SCHEMA_VERSION) {
            policies = new PolicyStoreWithActivation(
                    policies,
                    new PostgresRiskMethodSelectionPolicyActivationStore(connections, false)
            );
        }
        return Optional.of(new Runtime(policies));
    }

    public record Runtime(RiskMethodSelectionPolicyStore policies) {
        public Runtime {
            policies = Objects.requireNonNull(policies, "policies");
        }
    }

    private record PolicyStoreWithActivation(
            RiskMethodSelectionPolicyStore delegate,
            RiskMethodSelectionPolicyActivationStore activations
    ) implements RiskMethodSelectionPolicyStore {
        private PolicyStoreWithActivation {
            delegate = Objects.requireNonNull(delegate, "delegate");
            activations = Objects.requireNonNull(activations, "activations");
        }

        @Override
        public RiskMethodSelectionPolicyInstallResult install(RbvmRiskMethodSelectionPolicy policy)
                throws IOException {
            return delegate.install(policy);
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByRevision(int revision)
                throws IOException {
            return delegate.findByRevision(revision);
        }

        @Override
        public Optional<RbvmRiskMethodSelectionPolicy> findByPolicySha256(String policySha256)
                throws IOException {
            return delegate.findByPolicySha256(policySha256);
        }

        @Override
        public Optional<RiskMethodSelectionPolicyActivationStore> activationStore() {
            return Optional.of(activations);
        }
    }
}
