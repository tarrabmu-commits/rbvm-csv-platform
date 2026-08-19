package io.rbvm.postgres;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

public final class PostgresFoundationSelfTest {
    private static final List<String> MIGRATION_RESOURCES = List.of(
            "/db/migration/V1__canonical_rbvm.sql",
            "/db/migration/V2__dashboard_views.sql",
            "/db/migration/V3__case_workflow_audit.sql",
            "/db/migration/V4__postgres_projection_runtime.sql",
            "/db/migration/V5__postgres_read_catalog.sql",
            "/db/migration/V6__explicit_finding_lifecycle.sql",
            "/db/migration/V7__vulnerability_intelligence.sql",
            "/db/migration/V8__operational_analytics.sql",
            "/db/migration/V9__applicability_persistence.sql",
            "/db/migration/V10__cvss_v31_base_persistence.sql",
            "/db/migration/V11__cisa_kev_persistence.sql"
    );

    private PostgresFoundationSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        parsesProjectionConfigurationWithoutLeakingDefaults();
        rejectsUnsafeProjectionConfiguration();
        sanitizesDatabaseErrors();
        splitsMigrationScriptsLexically();
        bundlesEveryMigrationInTheRuntime();
        operationalAnalyticsPreservesEvidenceSemantics();
        applicabilityPersistencePreservesEvidenceSemantics();
        cvssV31PersistencePreservesEvidenceSemantics();
        cisaKevPersistencePreservesSnapshotBoundEvidenceSemantics();
        PostgresMigratorSelfTest.main(args);
        PostgresProjectionJdbcSelfTest.main(args);
        PostgresApplicabilityImporterSelfTest.main(args);
        PostgresCvssV31ImporterSelfTest.main(args);
        PostgresCisaKevImporterSelfTest.main(args);
        PostgresCvssV31EvidenceReaderSelfTest.main(args);
        PostgresCisaKevEvidenceReaderSelfTest.main(args);
        PostgresApplicabilityFindingExporterSelfTest.main(args);
        PostgresApplicabilityAwareCatalogSelfTest.main(args);
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
        for (String name : MIGRATION_RESOURCES) {
            String script = resource(name);
            List<String> statements = SqlScriptParser.statements(script);
            assert !statements.isEmpty() : name;
            assert statements.stream().noneMatch(sql -> sql.equalsIgnoreCase("BEGIN")) : name;
            assert statements.stream().noneMatch(sql -> sql.equalsIgnoreCase("COMMIT")) : name;
        }
    }

    private static void operationalAnalyticsPreservesEvidenceSemantics() throws Exception {
        String script = resource("/db/migration/V8__operational_analytics.sql");
        assert script.contains("OBSERVED_ONLY");
        assert script.contains("sp.contract_id = 'WAZUH_CSV_V2'");
        assert script.contains("No event is created from snapshot absence");
        assert !script.contains("remediated = active_keys - current_keys");
        assert !script.contains("priority_tier");
        assert !script.contains("SLA_Days");
    }

    private static void applicabilityPersistencePreservesEvidenceSemantics() throws Exception {
        String script = resource("/db/migration/V9__applicability_persistence.sql");
        assert script.contains("REFERENCES rbvm.exposure(tenant_id, id)");
        assert script.contains("f.exposure_id AS finding_id");
        assert script.contains("COALESCE(a.status, 'UNKNOWN')");
        assert script.contains("(a.id IS NOT NULL) AS applicability_assessed");
        assert script.contains("UNIQUE (tenant_id, finding_id, evaluated_at)");
        assert !script.contains("priority_tier");
        assert !script.contains("risk_score");
        assert !script.contains("SLA");
    }

    private static void cvssV31PersistencePreservesEvidenceSemantics() throws Exception {
        String script = resource("/db/migration/V10__cvss_v31_base_persistence.sql");
        assert script.contains("CREATE TABLE rbvm.cvss_v31_base_evidence");
        assert script.contains("cvss_version = '3.1'");
        assert script.contains("base_score BETWEEN 0.0 AND 10.0");
        assert script.contains("vector LIKE 'CVSS:3.1/%'");
        assert script.contains("UNIQUE (tenant_id, vulnerability_id, cvss_source, observed_at)");
        assert script.contains("DISTINCT ON (tenant_id, vulnerability_id, cvss_source)");
        assert script.contains("c.vulnerability_id = f.vulnerability_id");
        assert script.contains("does not arbitrate between sources");
        assert !script.contains("priority_tier");
        assert !script.contains("risk_score");
        assert !script.contains("epss_probability");
        assert !script.contains("known_exploited");
        assert !script.contains("SLA_Days");
    }

    private static void cisaKevPersistencePreservesSnapshotBoundEvidenceSemantics() throws Exception {
        String script = resource("/db/migration/V11__cisa_kev_persistence.sql");
        assert script.contains("CREATE TABLE rbvm.cisa_kev_catalog_snapshot");
        assert script.contains("CREATE TABLE rbvm.cisa_kev_evidence");
        assert script.contains("UNIQUE (tenant_id, kev_source, observed_at)");
        assert script.contains("UNIQUE (tenant_id, vulnerability_id, snapshot_id)");
        assert script.contains("REFERENCES rbvm.cisa_kev_catalog_snapshot(tenant_id, id)");
        assert script.contains("kev_status IN ('LISTED', 'NOT_LISTED')");
        assert script.contains("kev_status = 'NOT_LISTED'");
        assert script.contains("kev_date_added IS NULL");
        assert script.contains("COALESCE(k.kev_status, 'UNKNOWN')");
        assert script.contains("(k.id IS NOT NULL) AS kev_evidence_observed");
        assert script.contains("DISTINCT ON (e.tenant_id, e.vulnerability_id, s.kev_source)");
        assert script.contains("UNKNOWN is never persisted as a");
        assert !script.contains("priority_tier");
        assert !script.contains("risk_score");
        assert !script.contains("epss_probability");
        assert !script.contains("SLA_Days");
    }

    private static String resource(String name) throws Exception {
        try (InputStream input = PostgresFoundationSelfTest.class.getResourceAsStream(name)) {
            assert input != null : name;
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
