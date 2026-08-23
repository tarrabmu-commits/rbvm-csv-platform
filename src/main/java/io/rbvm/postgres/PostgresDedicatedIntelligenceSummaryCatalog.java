package io.rbvm.postgres;

import io.rbvm.domain.CaseActionCommand;
import io.rbvm.domain.CaseAuditEvent;
import io.rbvm.domain.CasePage;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.CatalogSnapshot;
import io.rbvm.domain.DomainCatalog;
import io.rbvm.domain.DomainMaterializationResult;
import io.rbvm.domain.PreparedCaseAction;
import io.rbvm.domain.VulnerabilityIntelligenceSummary;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Replaces only aggregate vulnerability-intelligence summary fields with values derived from the
 * independent current CVSS v3.1, FIRST EPSS, and CISA KEV evidence stores.
 *
 * <p>The legacy priority distribution is deliberately preserved. Priority is a separate policy
 * layer and is not recomputed or inferred from dedicated evidence here.</p>
 */
public final class PostgresDedicatedIntelligenceSummaryCatalog implements DomainCatalog {
    private static final String TENANT_KEY = "local";

    private final DomainCatalog delegate;
    private final JdbcConnectionFactory connections;
    private final Clock clock;

    public PostgresDedicatedIntelligenceSummaryCatalog(
            DomainCatalog delegate,
            JdbcConnectionFactory connections
    ) {
        this(delegate, connections, Clock.systemUTC());
    }

    PostgresDedicatedIntelligenceSummaryCatalog(
            DomainCatalog delegate,
            JdbcConnectionFactory connections,
            Clock clock
    ) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.connections = Objects.requireNonNull(connections, "connections");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String backend() {
        return delegate.backend();
    }

    @Override
    public DomainMaterializationResult materialize(
            UUID importId, Path csvPath, String sourceProfileId, String contractId
    ) throws IOException {
        return delegate.materialize(importId, csvPath, sourceProfileId, contractId);
    }

    @Override
    public CatalogSnapshot snapshot() {
        return replaceSummary(delegate.snapshot());
    }

    @Override
    public CasePage queryCases(CaseQuery query) {
        CasePage page = delegate.queryCases(query);
        return new CasePage(
                page.catalogRevision(),
                replaceSummary(page.summary()),
                page.cases(),
                page.nextCursor()
        );
    }

    @Override
    public Optional<Map<String, Object>> caseDetail(String caseId) {
        return delegate.caseDetail(caseId);
    }

    @Override
    public PreparedCaseAction prepareCaseAction(
            long sequence,
            String caseId,
            CaseActionCommand command,
            String idempotencyKey,
            String actorId,
            String actorAssurance,
            Instant occurredAt
    ) {
        return delegate.prepareCaseAction(
                sequence, caseId, command, idempotencyKey, actorId, actorAssurance, occurredAt);
    }

    @Override
    public Map<String, Object> applyCaseEvent(CaseAuditEvent event) {
        return delegate.applyCaseEvent(event);
    }

    @Override
    public boolean isMaterialized(UUID importId) {
        return delegate.isMaterialized(importId);
    }

    CatalogSnapshot replaceSummary(CatalogSnapshot base) {
        VulnerabilityIntelligenceSummary intelligence = dedicatedSummary(
                base.vulnerabilityIntelligence().priorityDistribution());
        return new CatalogSnapshot(
                base.materializedImports(),
                base.observations(),
                base.importObservationLinks(),
                base.assets(),
                base.vulnerabilities(),
                base.components(),
                base.exposures(),
                base.cases(),
                base.openCases(),
                base.autoClosedCases(),
                base.exposuresWithSeverityChanges(),
                base.exposuresWithTimestampConflicts(),
                base.currentCaseSeverityDistribution(),
                base.caseStatusDistribution(),
                intelligence
        );
    }

    private VulnerabilityIntelligenceSummary dedicatedSummary(Map<String, Long> priorities) {
        try (Connection connection = connections.open()) {
            UUID tenantId = tenantId(connection);
            if (tenantId == null) {
                return new VulnerabilityIntelligenceSummary(0, 0, 0, 0, null, null, priorities);
            }
            try (PreparedStatement statement = connection.prepareStatement(summarySql())) {
                for (int index = 1; index <= 7; index++) {
                    statement.setObject(index, tenantId);
                }
                statement.setTimestamp(8, Timestamp.from(
                        clock.instant().minus(VulnerabilityIntelligenceSummary.FRESHNESS_WINDOW)));
                try (ResultSet rows = statement.executeQuery()) {
                    if (!rows.next()) {
                        return new VulnerabilityIntelligenceSummary(
                                0, 0, 0, 0, null, null, priorities);
                    }
                    Timestamp oldest = rows.getTimestamp("oldest_observed_at");
                    Timestamp newest = rows.getTimestamp("newest_observed_at");
                    return new VulnerabilityIntelligenceSummary(
                            rows.getLong("enriched_vulnerabilities"),
                            rows.getLong("unenriched_vulnerabilities"),
                            rows.getLong("stale_vulnerabilities"),
                            rows.getLong("known_exploited_vulnerabilities"),
                            oldest == null ? null : oldest.toInstant(),
                            newest == null ? null : newest.toInstant(),
                            priorities
                    );
                }
            }
        } catch (SQLException exception) {
            throw new UncheckedIOException(
                    PostgresErrors.sanitized(
                            "PostgreSQL dedicated intelligence summary read failed", exception));
        }
    }

    private static String summarySql() {
        return """
                WITH active_vulnerability AS (
                    SELECT DISTINCT c.vulnerability_id AS id
                    FROM rbvm.vulnerability_case c
                    WHERE c.tenant_id = ?
                ),
                cvss AS (
                    SELECT e.vulnerability_id,
                           count(*) AS source_count,
                           max(e.observed_at) AS latest_observed_at
                    FROM rbvm.current_cvss_v31_base_evidence e
                    JOIN active_vulnerability a ON a.id = e.vulnerability_id
                    WHERE e.tenant_id = ?
                    GROUP BY e.vulnerability_id
                ),
                epss AS (
                    SELECT e.vulnerability_id,
                           count(*) AS source_count,
                           max(e.observed_at) AS latest_observed_at
                    FROM rbvm.current_epss_evidence e
                    JOIN active_vulnerability a ON a.id = e.vulnerability_id
                    WHERE e.tenant_id = ?
                    GROUP BY e.vulnerability_id
                ),
                kev AS (
                    SELECT e.vulnerability_id,
                           count(*) AS source_count,
                           count(*) FILTER (WHERE e.kev_status = 'LISTED') AS listed_count,
                           max(e.observed_at) AS latest_observed_at
                    FROM rbvm.current_cisa_kev_evidence e
                    JOIN active_vulnerability a ON a.id = e.vulnerability_id
                    WHERE e.tenant_id = ?
                    GROUP BY e.vulnerability_id
                ),
                per_vulnerability AS (
                    SELECT a.id,
                           coalesce(cvss.source_count, 0)
                               + coalesce(epss.source_count, 0)
                               + coalesce(kev.source_count, 0) AS evidence_count,
                           greatest(
                               cvss.latest_observed_at,
                               epss.latest_observed_at,
                               kev.latest_observed_at
                           ) AS latest_observed_at,
                           coalesce(kev.source_count, 0) AS kev_source_count,
                           coalesce(kev.listed_count, 0) AS kev_listed_count
                    FROM active_vulnerability a
                    LEFT JOIN cvss ON cvss.vulnerability_id = a.id
                    LEFT JOIN epss ON epss.vulnerability_id = a.id
                    LEFT JOIN kev ON kev.vulnerability_id = a.id
                ),
                all_current_evidence AS (
                    SELECT e.observed_at
                    FROM rbvm.current_cvss_v31_base_evidence e
                    JOIN active_vulnerability a ON a.id = e.vulnerability_id
                    WHERE e.tenant_id = ?
                    UNION ALL
                    SELECT e.observed_at
                    FROM rbvm.current_epss_evidence e
                    JOIN active_vulnerability a ON a.id = e.vulnerability_id
                    WHERE e.tenant_id = ?
                    UNION ALL
                    SELECT e.observed_at
                    FROM rbvm.current_cisa_kev_evidence e
                    JOIN active_vulnerability a ON a.id = e.vulnerability_id
                    WHERE e.tenant_id = ?
                )
                SELECT
                    count(*) FILTER (WHERE evidence_count > 0) AS enriched_vulnerabilities,
                    count(*) FILTER (WHERE evidence_count = 0) AS unenriched_vulnerabilities,
                    count(*) FILTER (
                        WHERE evidence_count > 0 AND latest_observed_at < ?
                    ) AS stale_vulnerabilities,
                    count(*) FILTER (
                        WHERE kev_source_count = 1 AND kev_listed_count = 1
                    ) AS known_exploited_vulnerabilities,
                    (SELECT min(observed_at) FROM all_current_evidence) AS oldest_observed_at,
                    (SELECT max(observed_at) FROM all_current_evidence) AS newest_observed_at
                FROM per_vulnerability
                """;
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
}
