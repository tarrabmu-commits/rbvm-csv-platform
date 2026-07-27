package io.rbvm.postgres;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public record PostgresProjectionSettings(
        boolean enabled,
        String jdbcUrl,
        String user,
        String password,
        boolean migrate
) {
    public PostgresProjectionSettings {
        if (enabled) {
            require(jdbcUrl, "RBVM_JDBC_URL");
            require(user, "RBVM_DB_USER");
            Objects.requireNonNull(password, "password");
            if (!jdbcUrl.startsWith("jdbc:postgresql:")) {
                throw new IllegalArgumentException(
                        "RBVM_JDBC_URL must begin with jdbc:postgresql:");
            }
            String normalizedUrl = jdbcUrl.toLowerCase(Locale.ROOT);
            if (normalizedUrl.contains("password=") || normalizedUrl.contains("user=")) {
                throw new IllegalArgumentException(
                        "Database credentials must use RBVM_DB_USER and RBVM_DB_PASSWORD, not the URL");
            }
        }
    }

    public static PostgresProjectionSettings fromEnvironment(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment");
        String backend = value(environment, "RBVM_PROJECTION_BACKEND", "DISABLED")
                .toUpperCase(Locale.ROOT);
        if (backend.equals("DISABLED") || backend.equals("LOCAL")) {
            return new PostgresProjectionSettings(false, null, null, null, false);
        }
        if (!backend.equals("POSTGRESQL") && !backend.equals("POSTGRES")) {
            throw new IllegalArgumentException(
                    "RBVM_PROJECTION_BACKEND must be DISABLED or POSTGRESQL");
        }
        boolean migrate = parseBoolean(value(environment, "RBVM_DB_MIGRATE", "true"));
        return new PostgresProjectionSettings(
                true,
                value(environment, "RBVM_JDBC_URL", null),
                value(environment, "RBVM_DB_USER", null),
                environment.getOrDefault("RBVM_DB_PASSWORD", ""),
                migrate
        );
    }

    @Override
    public String toString() {
        return "PostgresProjectionSettings[enabled=" + enabled
                + ", jdbcUrl=" + (enabled ? "<configured>" : "null")
                + ", user=" + (enabled ? "<configured>" : "null")
                + ", password=<redacted>, migrate=" + migrate + ']';
    }

    private static String value(Map<String, String> environment, String key, String fallback) {
        String value = environment.get(key);
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static boolean parseBoolean(String value) {
        if ("true".equalsIgnoreCase(value)) {
            return true;
        }
        if ("false".equalsIgnoreCase(value)) {
            return false;
        }
        throw new IllegalArgumentException("RBVM_DB_MIGRATE must be true or false");
    }

    private static void require(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required for the PostgreSQL projection");
        }
    }
}
