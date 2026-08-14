package io.rbvm.postgres;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

public final class PostgresFoundationSelfTest {
    private PostgresFoundationSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        parsesProjectionConfigurationWithoutLeakingDefaults();
        rejectsUnsafeProjectionConfiguration();
        sanitizesDatabaseErrors();
        splitsMigrationScriptsLexically();
        bundlesEveryMigrationInTheRuntime();
        PostgresMigratorSelfTest.main(args);
        PostgresProjectionJdbcSelfTest.main(args);
        System.out.println("PostgresFoundationSelfTest: PASS");
    }

    private static void parsesProjectionConfigurationWithoutLeakingDefaults() {
        PostgresProjectionSettings disabled = PostgresProjectionSettings.fromEnvironment(Map.of());
        assert !disabled.enabled();

        PostgresProjectionSettings enabled = PostgresProjectionSettings.fromEnvironment(Map.of(
                "RBVM_PROJECTION_BACKEND", "postgresql",
                "RBVM_JDBC_URL", "jdbc:postgresql://db.internal/rbvm",
                "RBVM_DB_USER", "rbvm_app",
                "RBVM_DB_PASSWORD", "secret",
                "RBVM_DB_MIGRATE", "false"
        ));
        assert enabled.enabled();
        assert !enabled.migrate();
        assert enabled.jdbcUrl().equals("jdbc:postgresql://db.internal/rbvm");
        assert enabled.user().equals("rbvm_app");
        assert enabled.password().equals("secret");
        assert !enabled.toString().contains("secret");
        assert !enabled.toString().contains("db.internal");
    }

    private static void rejectsUnsafeProjectionConfiguration() {
        assertRejected(Map.of("RBVM_PROJECTION_BACKEND", "unknown"));
        assertRejected(Map.of(
                "RBVM_PROJECTION_BACKEND", "postgresql",
                "RBVM_JDBC_URL", "jdbc:mysql://db/rbvm",
                "RBVM_DB_USER", "rbvm"
        ));
        assertRejected(Map.of(
                "RBVM_PROJECTION_BACKEND", "postgresql",
                "RBVM_JDBC_URL", "jdbc:postgresql://db/rbvm"
        ));
        assertRejected(Map.of(
                "RBVM_PROJECTION_BACKEND", "postgresql",
                "RBVM_JDBC_URL", "jdbc:postgresql://db/rbvm",
                "RBVM_DB_USER", "rbvm",
                "RBVM_DB_MIGRATE", "sometimes"
        ));
        assertRejected(Map.of(
                "RBVM_PROJECTION_BACKEND", "postgresql",
                "RBVM_JDBC_URL", "jdbc:postgresql://db/rbvm?password=inline",
                "RBVM_DB_USER", "rbvm"
        ));
    }

    private static void assertRejected(Map<String, String> environment) {
        boolean rejected = false;
        try {
            PostgresProjectionSettings.fromEnvironment(environment);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        assert rejected;
    }

    private static void sanitizesDatabaseErrors() {
        SQLException source = new SQLException(
                "connection failed for jdbc:postgresql://db/rbvm?password=top-secret",
                "08001"
        );
        String message = PostgresErrors.sanitized("PostgreSQL connection failed", source)
                .getMessage();
        assert message.contains("08001");
        assert !message.contains("top-secret");
        assert !message.contains("jdbc:postgresql");
    }

    private static void splitsMigrationScriptsLexically() {
        String script = """
                BEGIN;
                -- a comment containing ; does not terminate a statement
                INSERT INTO example(value) VALUES ('semi;colon');
                /* outer ; /* nested ; */ still comment */
                COMMENT ON TABLE example IS 'quoted '' value;';
                CREATE FUNCTION example_fn() RETURNS trigger AS $body$
                BEGIN
                    RAISE EXCEPTION 'blocked;';
                END;
                $body$ LANGUAGE plpgsql;
                COMMIT;
                """;
        List<String> statements = SqlScriptParser.statements(script);
        assert statements.size() == 3 : statements;
        assert statements.get(0).contains("semi;colon");
        assert statements.get(1).contains("quoted '' value;");
    }

    private static void bundlesEveryMigrationInTheRuntime() throws Exception {
        for (int version = 1; version <= 5; version++) {
            String prefix = "/db/migration/V" + version + "__";
            String name = switch (version) {
                case 1 -> prefix + "canonical_rbvm.sql";
                case 2 -> prefix + "dashboard_views.sql";
                case 3 -> prefix + "case_workflow_audit.sql";
                case 4 -> prefix + "postgres_projection_runtime.sql";
                case 5 -> prefix + "postgres_read_catalog.sql";
                default -> throw new AssertionError(version);
            };
            try (InputStream input = PostgresFoundationSelfTest.class.getResourceAsStream(name)) {
                assert input != null : name;
                String script = new String(input.readAllBytes(), StandardCharsets.UTF_8);
                List<String> statements = SqlScriptParser.statements(script);
                assert !statements.isEmpty();
                assert statements.stream().noneMatch(sql -> sql.equalsIgnoreCase("BEGIN"));
                assert statements.stream().noneMatch(sql -> sql.equalsIgnoreCase("COMMIT"));
            }
        }
    }
}
