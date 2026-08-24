package io.rbvm.postgres;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Builds the opt-in automation controller only when explicit automation settings are present. */
public final class PublicIntelligenceAutomationRuntimeFactory {
    private PublicIntelligenceAutomationRuntimeFactory() {
    }

    public static Optional<PublicIntelligenceAutomationController> fromEnvironment(
            Map<String, String> environment,
            Optional<? extends PublicIntelligenceSyncTrigger> trigger
    ) {
        Objects.requireNonNull(environment, "environment");
        Objects.requireNonNull(trigger, "trigger");
        PublicIntelligenceAutomationSettings automation =
                PublicIntelligenceAutomationSettings.fromEnvironment(environment);
        if (!automation.enabled()) return Optional.empty();

        PostgresProjectionSettings settings =
                PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) {
            throw new IllegalArgumentException(
                    "Public intelligence automation requires RBVM_PROJECTION_BACKEND=POSTGRESQL");
        }
        PublicIntelligenceSyncTrigger sync = trigger.orElseThrow(() ->
                new IllegalArgumentException(
                        "Public intelligence automation requires the V31 synchronization runtime"));
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        PostgresPublicIntelligenceSyncJobStore jobs =
                new PostgresPublicIntelligenceSyncJobStore(connections, false);
        PublicIntelligenceAutomationPlanExecutor plans =
                new PublicIntelligenceAutomationPlanExecutor(
                        sync,
                        new PostgresPublicIntelligenceSyncCompletionReader(jobs),
                        new PostgresPublicIntelligenceNvdBootstrapStateReader(connections));
        return Optional.of(new PublicIntelligenceAutomationController(automation, plans));
    }
}
