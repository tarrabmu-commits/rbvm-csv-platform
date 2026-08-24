package io.rbvm.postgres;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Product runtime assembly for manual/background public-intelligence synchronization. */
public final class PublicIntelligenceOrchestrationRuntimeFactory {
    private PublicIntelligenceOrchestrationRuntimeFactory() {
    }

    public static Optional<PublicIntelligenceSyncCoordinator> fromEnvironment(
            Map<String, String> environment,
            Path dataDirectory
    ) throws IOException {
        Objects.requireNonNull(environment, "environment");
        Objects.requireNonNull(dataDirectory, "dataDirectory");
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) return Optional.empty();
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        PostgresPublicIntelligenceSyncJobStore jobs =
                new PostgresPublicIntelligenceSyncJobStore(connections, false);
        PostgresPublicIntelligenceStore sources =
                new PostgresPublicIntelligenceStore(connections, false);
        PostgresPublicIntelligenceCurrentCveReader currentCves =
                new PostgresPublicIntelligenceCurrentCveReader(connections);
        SubprocessPublicIntelligenceSourcePipeline pipeline =
                new SubprocessPublicIntelligenceSourcePipeline(environment);
        int workers = parseWorkers(environment.get("RBVM_INTELLIGENCE_SYNC_WORKERS"));
        return Optional.of(new PublicIntelligenceSyncCoordinator(
                jobs,
                sources,
                currentCves,
                pipeline,
                dataDirectory.resolve("public-intelligence-sync-work"),
                workers));
    }

    private static int parseWorkers(String value) {
        if (value == null || value.isBlank()) return 2;
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < 1 || parsed > 4) {
                throw new IllegalArgumentException(
                        "RBVM_INTELLIGENCE_SYNC_WORKERS must be between 1 and 4");
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(
                    "RBVM_INTELLIGENCE_SYNC_WORKERS must be an integer", exception);
        }
    }
}
