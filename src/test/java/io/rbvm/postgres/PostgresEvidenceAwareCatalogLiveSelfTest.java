package io.rbvm.postgres;

import io.rbvm.domain.CasePage;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.DomainCatalog;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Live PostgreSQL proof that Finding reads use dedicated current intelligence without precedence. */
public final class PostgresEvidenceAwareCatalogLiveSelfTest {
    private static final UUID SNAPSHOT_A = UUID.fromString("a1000000-0000-4000-8000-000000000001");
    private static final UUID SNAPSHOT_B = UUID.fromString("a1000000-0000-4000-8000-000000000002");
    private static final UUID EVIDENCE_A = UUID.fromString("b1000000-0000-4000-8000-000000000001");
    private static final UUID EVIDENCE_B = UUID.fromString("b1000000-0000-4000-8000-000000000002");
    private static final Instant OBSERVED_A = Instant.parse("2026-08-22T01:00:00Z");
    private static final Instant OBSERVED_B = Instant.parse("2026-08-22T01:01:00Z");

    private PostgresEvidenceAwareCatalogLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");
        JdbcConnectionFactory ownerConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        int schemaVersion = new PostgresMigrator(ownerConnections).installedVersion();
        require(schemaVersion >= 12, "dedicated intelligence views require PostgreSQL V12+");

        Target target = target(ownerConnections);
        installRuntimeRole(ownerConnections);
        setRuntimePassword(ownerConnections);
        JdbcConnectionFactory runtimeConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), "rbvm_runtime", "rbvm-live-test");
        DomainCatalog catalog = new PostgresEvidenceAwareCatalog(
                new PostgresReadCatalog(runtimeConnections), runtimeConnections);

        Map<String, Object> before = findCase(catalog, target.cveId());
        Map<String, Object> beforeIntel = intelligence(before);
        verifyFamilyState(runtimeConnections, target, beforeIntel,
                "rbvm.current_cvss_v31_base_evidence", "cvssEvidenceState", "cvssBaseScore");
        verifyFamilyState(runtimeConnections, target, beforeIntel,
                "rbvm.current_epss_evidence", "epssEvidenceState", "epssProbability");
        verifyKevState(runtimeConnections, target, beforeIntel);

        seedTwoAdditionalKevSources(ownerConnections, target);
        Map<String, Object> ambiguous = findCase(catalog, target.cveId());
        Map<String, Object> ambiguousIntel = intelligence(ambiguous);
        require("AMBIGUOUS".equals(ambiguousIntel.get("kevEvidenceState")),
                "multiple current KEV sources must be AMBIGUOUS");
        require(ambiguousIntel.get("knownExploited") == null,
                "ambiguous KEV must not choose a boolean membership value");
        require(ambiguousIntel.get("kevStatus") == null,
                "ambiguous KEV must not choose a catalog membership status");
        require(((Number) ambiguousIntel.get("kevSourceCount")).intValue() >= 2,
                "ambiguous KEV must expose the current source count");

        require(!containsCve(catalog.queryCases(withKevFilter(true)), target.cveId()),
                "ambiguous KEV must not satisfy the LISTED boolean filter");
        require(!containsCve(catalog.queryCases(withKevFilter(false)), target.cveId()),
                "ambiguous KEV must not satisfy the NOT_LISTED boolean filter");

        System.out.println(
                "PostgresEvidenceAwareCatalogLiveSelfTest: PASS dedicated_reads=PASS "
                        + "runtime_role=PASS missing_present_ambiguous=PASS "
                        + "no_hidden_precedence=PASS kev_filter=PASS");
    }

    private static void verifyFamilyState(
            JdbcConnectionFactory connections,
            Target target,
            Map<String, Object> intelligence,
            String view,
            String stateField,
            String valueField
    ) throws SQLException {
        long count = currentCount(connections, target, view);
        String expected = count == 0 ? "MISSING" : count == 1 ? "PRESENT" : "AMBIGUOUS";
        require(expected.equals(intelligence.get(stateField)),
                stateField + " must match current dedicated source cardinality");
        if (count == 1) {
            require(intelligence.get(valueField) != null,
                    valueField + " must be exposed for one unambiguous current source");
        } else {
            require(intelligence.get(valueField) == null,
                    valueField + " must remain null when missing or ambiguous");
        }
    }

    private static void verifyKevState(
            JdbcConnectionFactory connections,
            Target target,
            Map<String, Object> intelligence
    ) throws SQLException {
        long count = currentCount(connections, target, "rbvm.current_cisa_kev_evidence");
        String expected = count == 0 ? "MISSING" : count == 1 ? "PRESENT" : "AMBIGUOUS";
        require(expected.equals(intelligence.get("kevEvidenceState")),
                "KEV evidence state must match current dedicated source cardinality");
        if (count == 0) {
            require("UNKNOWN".equals(intelligence.get("kevStatus")),
                    "missing KEV evidence must be UNKNOWN, not NOT_LISTED");
            require(intelligence.get("knownExploited") == null,
                    "missing KEV evidence must not invent false");
        } else if (count == 1) {
            require(intelligence.get("knownExploited") instanceof Boolean,
                    "one KEV source must expose explicit LISTED/NOT_LISTED membership");
        } else {
            require(intelligence.get("knownExploited") == null,
                    "multiple KEV sources must not choose a membership value");
        }
    }

    private static CaseQuery withKevFilter(boolean listed) {
        return new CaseQuery(100, null, java.util.Set.of(), java.util.Set.of(),
                null, null, java.util.Set.of(), listed);
    }

    private static boolean containsCve(CasePage page, String cveId) {
        return page.cases().stream().anyMatch(item -> cveId.equals(item.get("cveId")));
    }

    private static Map<String, Object> findCase(DomainCatalog catalog, String cveId) {
        CasePage page = catalog.queryCases(CaseQuery.firstPage(100));
        return page.cases().stream()
                .filter(item -> cveId.equals(item.get("cveId")))
                .findFirst()
                .orElseThrow(() -> new AssertionError("seeded canonical CVE was not returned"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> intelligence(Map<String, Object> item) {
        Object value = item.get("vulnerabilityIntelligence");
        require(value instanceof Map<?, ?>, "Finding must expose vulnerabilityIntelligence");
        return (Map<String, Object>) value;
    }

    private static long currentCount(
            JdbcConnectionFactory connections, Target target, String view
    ) throws SQLException {
        require(List.of(
                "rbvm.current_cvss_v31_base_evidence",
                "rbvm.current_epss_evidence",
                "rbvm.current_cisa_kev_evidence").contains(view), "unexpected evidence view");
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT count(*) FROM " + view
                             + " WHERE tenant_id = ? AND vulnerability_id = ?")) {
            statement.setObject(1, target.tenantId());
            statement.setObject(2, target.vulnerabilityId());
            try (ResultSet rows = statement.executeQuery()) {
                require(rows.next(), "count query must return one row");
                return rows.getLong(1);
            }
        }
    }

    private static Target target(JdbcConnectionFactory connections) throws SQLException {
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT c.tenant_id, c.vulnerability_id, v.cve_id
                     FROM rbvm.vulnerability_case c
                     JOIN rbvm.vulnerability v ON v.id = c.vulnerability_id
                     ORDER BY c.created_at, c.id
                     LIMIT 1
                     """)) {
            try (ResultSet rows = statement.executeQuery()) {
                require(rows.next(), "V22 live test must seed at least one canonical case");
                return new Target(
                        rows.getObject(1, UUID.class),
                        rows.getObject(2, UUID.class),
                        rows.getString(3));
            }
        }
    }

    private static void installRuntimeRole(JdbcConnectionFactory connections) throws Exception {
        String script = Files.readString(Path.of("db/security/runtime-role.sql"));
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            statement.execute(script);
        }
    }

    private static void setRuntimePassword(JdbcConnectionFactory connections) throws SQLException {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            statement.execute("ALTER ROLE rbvm_runtime PASSWORD 'rbvm-live-test'");
        }
    }

    private static void seedTwoAdditionalKevSources(
            JdbcConnectionFactory connections, Target target
    ) throws SQLException {
        try (Connection connection = connections.open()) {
            connection.setAutoCommit(false);
            insertKevSnapshot(connection, SNAPSHOT_A, target.tenantId(),
                    "https://example.invalid/rbvm-live-kev-a", OBSERVED_A, "a".repeat(64));
            insertKevSnapshot(connection, SNAPSHOT_B, target.tenantId(),
                    "https://example.invalid/rbvm-live-kev-b", OBSERVED_B, "b".repeat(64));
            insertKevEvidence(connection, EVIDENCE_A, target, SNAPSHOT_A,
                    "NOT_LISTED", null, null, null, "c".repeat(64));
            insertKevEvidence(connection, EVIDENCE_B, target, SNAPSHOT_B,
                    "LISTED", LocalDate.parse("2026-08-01"), LocalDate.parse("2026-08-22"),
                    "UNKNOWN", "d".repeat(64));
            connection.commit();
        }
    }

    private static void insertKevSnapshot(
            Connection connection, UUID id, UUID tenantId, String source,
            Instant observedAt, String sha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.cisa_kev_catalog_snapshot(
                    id, tenant_id, catalog_version, catalog_sha256, catalog_count,
                    kev_source, observed_at, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """)) {
            statement.setObject(1, id);
            statement.setObject(2, tenantId);
            statement.setString(3, "rbvm-live-test");
            statement.setString(4, sha256);
            statement.setInt(5, 1);
            statement.setString(6, source);
            statement.setTimestamp(7, Timestamp.from(observedAt));
            statement.setTimestamp(8, Timestamp.from(observedAt));
            statement.executeUpdate();
        }
    }

    private static void insertKevEvidence(
            Connection connection, UUID id, Target target, UUID snapshotId, String status,
            LocalDate added, LocalDate due, String ransomware, String sha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.cisa_kev_evidence(
                    id, tenant_id, vulnerability_id, snapshot_id, kev_status,
                    kev_date_added, kev_due_date, known_ransomware_campaign_use,
                    ingested_at, evidence_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """)) {
            statement.setObject(1, id);
            statement.setObject(2, target.tenantId());
            statement.setObject(3, target.vulnerabilityId());
            statement.setObject(4, snapshotId);
            statement.setString(5, status);
            statement.setObject(6, added == null ? null : java.sql.Date.valueOf(added));
            statement.setObject(7, due == null ? null : java.sql.Date.valueOf(due));
            statement.setString(8, ransomware);
            statement.setTimestamp(9, Timestamp.from(OBSERVED_B));
            statement.setString(10, sha256);
            statement.executeUpdate();
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private record Target(UUID tenantId, UUID vulnerabilityId, String cveId) {
    }
}
