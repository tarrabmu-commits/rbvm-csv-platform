package io.rbvm.postgres;

import java.time.Duration;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Explicit opt-in runtime configuration for automatic public-intelligence synchronization. */
public record PublicIntelligenceAutomationSettings(
        boolean nvdBootstrapOnStartup,
        Set<PostgresPublicIntelligenceStore.Provider> startupRefreshProviders,
        Map<PostgresPublicIntelligenceStore.Provider, Duration> scheduledRefreshIntervals
) {
    private static final long MIN_SCHEDULE_SECONDS = 3_600L;
    private static final long MAX_SCHEDULE_SECONDS = 31L * 24L * 60L * 60L;

    public PublicIntelligenceAutomationSettings {
        Objects.requireNonNull(startupRefreshProviders, "startupRefreshProviders");
        Objects.requireNonNull(scheduledRefreshIntervals, "scheduledRefreshIntervals");
        startupRefreshProviders = startupRefreshProviders.isEmpty()
                ? Set.of()
                : Collections.unmodifiableSet(EnumSet.copyOf(startupRefreshProviders));
        EnumMap<PostgresPublicIntelligenceStore.Provider, Duration> copy =
                new EnumMap<>(PostgresPublicIntelligenceStore.Provider.class);
        copy.putAll(scheduledRefreshIntervals);
        for (Map.Entry<PostgresPublicIntelligenceStore.Provider, Duration> entry : copy.entrySet()) {
            Objects.requireNonNull(entry.getKey(), "scheduled provider");
            Duration interval = Objects.requireNonNull(entry.getValue(), "scheduled interval");
            long seconds = interval.getSeconds();
            if (seconds < MIN_SCHEDULE_SECONDS || seconds > MAX_SCHEDULE_SECONDS) {
                throw new IllegalArgumentException(
                        "public-intelligence scheduled intervals must be between 3600 and 2678400 seconds");
            }
        }
        scheduledRefreshIntervals = Collections.unmodifiableMap(copy);
    }

    public boolean enabled() {
        return nvdBootstrapOnStartup
                || !startupRefreshProviders.isEmpty()
                || !scheduledRefreshIntervals.isEmpty();
    }

    public static PublicIntelligenceAutomationSettings fromEnvironment(
            Map<String, String> environment
    ) {
        Objects.requireNonNull(environment, "environment");
        boolean bootstrap = parseBoolean(
                environment.get("RBVM_INTELLIGENCE_NVD_BOOTSTRAP_ON_STARTUP"),
                "RBVM_INTELLIGENCE_NVD_BOOTSTRAP_ON_STARTUP");
        Set<PostgresPublicIntelligenceStore.Provider> startup = parseProviders(
                environment.get("RBVM_INTELLIGENCE_STARTUP_REFRESH_PROVIDERS"));
        EnumMap<PostgresPublicIntelligenceStore.Provider, Duration> scheduled =
                new EnumMap<>(PostgresPublicIntelligenceStore.Provider.class);
        schedule(environment, scheduled, PostgresPublicIntelligenceStore.Provider.NVD,
                "RBVM_INTELLIGENCE_SCHEDULE_NVD_SECONDS");
        schedule(environment, scheduled, PostgresPublicIntelligenceStore.Provider.FIRST_EPSS,
                "RBVM_INTELLIGENCE_SCHEDULE_FIRST_EPSS_SECONDS");
        schedule(environment, scheduled, PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                "RBVM_INTELLIGENCE_SCHEDULE_CISA_KEV_SECONDS");
        schedule(environment, scheduled, PostgresPublicIntelligenceStore.Provider.CVE_PROGRAM,
                "RBVM_INTELLIGENCE_SCHEDULE_CVE_PROGRAM_SECONDS");
        return new PublicIntelligenceAutomationSettings(bootstrap, startup, scheduled);
    }

    private static void schedule(
            Map<String, String> environment,
            EnumMap<PostgresPublicIntelligenceStore.Provider, Duration> scheduled,
            PostgresPublicIntelligenceStore.Provider provider,
            String key
    ) {
        String raw = environment.get(key);
        if (raw == null || raw.isBlank() || "0".equals(raw.trim())) return;
        try {
            long seconds = Long.parseLong(raw.trim());
            if (seconds < MIN_SCHEDULE_SECONDS || seconds > MAX_SCHEDULE_SECONDS) {
                throw new IllegalArgumentException(
                        key + " must be 0/blank or between 3600 and 2678400 seconds");
            }
            scheduled.put(provider, Duration.ofSeconds(seconds));
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(key + " must be an integer number of seconds", exception);
        }
    }

    private static Set<PostgresPublicIntelligenceStore.Provider> parseProviders(String raw) {
        if (raw == null || raw.isBlank()) return Set.of();
        EnumSet<PostgresPublicIntelligenceStore.Provider> providers =
                EnumSet.noneOf(PostgresPublicIntelligenceStore.Provider.class);
        for (String token : raw.split(",")) {
            String value = token.trim();
            if (value.isEmpty()) continue;
            try {
                providers.add(PostgresPublicIntelligenceStore.Provider.valueOf(
                        value.toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException exception) {
                throw new IllegalArgumentException(
                        "RBVM_INTELLIGENCE_STARTUP_REFRESH_PROVIDERS contains unsupported provider: "
                                + value,
                        exception);
            }
        }
        return providers;
    }

    private static boolean parseBoolean(String raw, String key) {
        if (raw == null || raw.isBlank() || "false".equalsIgnoreCase(raw.trim())) return false;
        if ("true".equalsIgnoreCase(raw.trim())) return true;
        throw new IllegalArgumentException(key + " must be true or false");
    }
}
