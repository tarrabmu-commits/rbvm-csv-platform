package io.rbvm.postgres;

import io.rbvm.domain.CasePage;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.CatalogSnapshot;
import io.rbvm.domain.DomainCatalog;
import io.rbvm.domain.VulnerabilityIntelligenceSummary;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

/** Live PostgreSQL proof that catalog summaries no longer use legacy embedded intelligence. */
public final class PostgresDedicatedIntelligenceSummaryLiveSelfTest {
    private static final String TENANT_KEY = "local";

    private PostgresDedicatedIntelligenceSummaryLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        int schemaVersion = new PostgresMigrator(connections).installedVersion();
        require(schemaVersion >= 12, "dedicated intelligence summary requires PostgreSQL V12+");

        PostgresReadCatalog legacyCatalog = new PostgresReadCatalog(connections);
        DomainCatalog catalog = new PostgresEvidenceAwareCatalog(legacyCatalog, connections);
        CatalogSnapshot legacy = legacyCatalog.snapshot();
        CatalogSnapshot dedicated = catalog.snapshot();
        VulnerabilityIntelligenceSummary summary = dedicated.vulnerabilityIntelligence();

        require(summary.priorityDistribution().equals(
                        legacy.vulnerabilityIntelligence().priorityDistribution()),
                "dedicated summary must preserve the separate legacy priority distribution");
        require(summary.enrichedVulnerabilities() + summary.unenrichedVulnerabilities()
                        == dedicated.vulnerabilities(),
                "every canonical observed CVE must be explicitly enriched or unenriched");

        long expectedKnownExploited = expectedUnambiguousListed(connections);
        require(summary.knownExploitedVulnerabilities() == expectedKnownExploited,
                "known-exploited summary must count only one-source unambiguous KEV LISTED evidence");

        EvidenceTimeRange range = evidenceTimeRange(connections);
        require(java.util.Objects.equals(summary.oldestObservedAt(), range.oldest()),
                "summary oldestObservedAt must come from current dedicated evidence");
        require(java.util.Objects.equals(summary.newestObservedAt(), range.newest()),
                "summary newestObservedAt must come from current dedicated evidence");

        CasePage page = catalog.queryCases(CaseQuery.firstPage(100));
        require(page.summary().vulnerabilityIntelligence().equals(summary),
                "Cases page summary and catalog summary must use the same dedicated evidence semantics");

        System.out.println(
                "PostgresDedicatedIntelligenceSummaryLiveSelfTest: PASS "
                        + "dedicated_summary=PASS kev_unambiguous=PASS "
                        + "freshness_provenance=PASS priority_separation=PASS");
    }

    private static long expectedUnambiguousListed(JdbcConnectionFactory connections)
            throws SQLException {
        try (Connection connection = connections.open()) {
            UUID tenantId = tenantId(connection);
            if (tenantId == null) return 0;
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT count(*)
                    FROM (
                        SELECT e.vulnerability_id
                        FROM rbvm.current_cisa_kev_evidence e
                        WHERE e.tenant_id = ?
                          AND EXISTS (
                              SELECT 1 FROM rbvm.observation o
                              WHERE o.tenant_id = ?
                                AND o.vulnerability_id = e.vulnerability_id
                          )
                        GROUP BY e.vulnerability_id
                        HAVING count(*) = 1
                           AND count(*) FILTER (WHERE e.kev_status = 'LISTED') = 1
                    ) eligible
                    """)) {
                statement.setObject(1, tenantId);
                statement.setObject(2, tenantId);
                try (ResultSet rows = statement.executeQuery()) {
                    require(rows.next(), "KEV summary reference query must return one row");
                    return rows.getLong(1);
                }
            }
        }
    }

    private static EvidenceTimeRange evidenceTimeRange(JdbcConnectionFactory connections)
            throws SQLException {
        try (Connection connection = connections.open()) {
            UUID tenantId = tenantId(connection);
            if (tenantId == null) return new EvidenceTimeRange(null, null);
            try (PreparedStatement statement = connection.prepareStatement("""
                    WITH active_vulnerability AS (
                        SELECT DISTINCT o.vulnerability_id
                        FROM rbvm.observation o
                        WHERE o.tenant_id = ?
                    ), all_current AS (
                        SELECT e.observed_at
                        FROM rbvm.current_cvss_v31_base_evidence e
                        JOIN active_vulnerability a ON a.vulnerability_id = e.vulnerability_id
                        WHERE e.tenant_id = ?
                        UNION ALL
                        SELECT e.observed_at
                        FROM rbvm.current_epss_evidence e
                        JOIN active_vulnerability a ON a.vulnerability_id = e.vulnerability_id
                        WHERE e.tenant_id = ?
                        UNION ALL
                        SELECT e.observed_at
                        FROM rbvm.current_cisa_kev_evidence e
                        JOIN active_vulnerability a ON a.vulnerability_id = e.vulnerability_id
                        WHERE e.tenant_id = ?
                    )
                    SELECT min(observed_at), max(observed_at) FROM all_current
                    """)) {
                for (int index = 1; index <= 4; index++) statement.setObject(index, tenantId);
                try (ResultSet rows = statement.executeQuery()) {
                    require(rows.next(), "evidence time-range query must return one row");
                    java.sql.Timestamp oldest = rows.getTimestamp(1);
                    java.sql.Timestamp newest = rows.getTimestamp(2);
                    return new EvidenceTimeRange(
                            oldest == null ? null : oldest.toInstant(),
                            newest == null ? null : newest.toInstant());
                }
            }
        }
    }

    private static UUID tenantId(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT id FROM rbvm.tenant WHERE tenant_key = ?")) {
            statement.setString(1, TENANT_KEY);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getObject(1, UUID.class) : null;
            }
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private record EvidenceTimeRange(java.time.Instant oldest, java.time.Instant newest) {
    }
}
