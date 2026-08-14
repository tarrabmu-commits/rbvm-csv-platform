package io.rbvm.postgres;

import io.rbvm.csv.CsvSeverity;
import io.rbvm.domain.CaseActionCommand;
import io.rbvm.domain.CaseAuditEvent;
import io.rbvm.domain.CasePage;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.CaseStatus;
import io.rbvm.domain.CatalogSnapshot;
import io.rbvm.domain.DomainCatalog;
import io.rbvm.domain.DomainMaterializationResult;
import io.rbvm.domain.InvalidCaseActionException;
import io.rbvm.domain.PreparedCaseAction;
import io.rbvm.domain.StaleCaseCursorException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** PostgreSQL read model used after the Increment 6 catalog cutover. */
public final class PostgresReadCatalog implements DomainCatalog {
    private static final String TENANT_KEY = "local";

    private final JdbcConnectionFactory connections;
    private final Clock clock;

    public PostgresReadCatalog(JdbcConnectionFactory connections) {
        this(connections, Clock.systemUTC());
    }

    PostgresReadCatalog(JdbcConnectionFactory connections, Clock clock) {
        this.connections = Objects.requireNonNull(connections, "connections");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String backend() {
        return "POSTGRESQL";
    }

    @Override
    public CatalogSnapshot snapshot() {
        try (Connection connection = connections.open()) {
            UUID tenantId = tenantId(connection);
            return tenantId == null ? emptySnapshot() : snapshot(connection, tenantId);
        } catch (SQLException exception) {
            throw readFailure(exception);
        }
    }

    @Override
    public CasePage queryCases(CaseQuery query) {
        Objects.requireNonNull(query, "query");
        try (Connection connection = connections.open()) {
            UUID tenantId = tenantId(connection);
            if (tenantId == null) {
                return new CasePage(0, emptySnapshot(), List.of(), null);
            }
            long revision = revision(connection, tenantId);
            int offset = decodeCursor(query.cursor(), revision);
            List<Object> parameters = new ArrayList<>();
            StringBuilder sql = new StringBuilder(caseSelect()).append(" WHERE c.tenant_id = ?");
            parameters.add(tenantId);
            appendFilters(sql, parameters, query);
            sql.append(caseOrder()).append(" LIMIT ? OFFSET ?");
            parameters.add(query.limit() + 1);
            parameters.add(offset);

            List<Map<String, Object>> cases = new ArrayList<>();
            try (PreparedStatement statement = connection.prepareStatement(sql.toString())) {
                bind(statement, parameters);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        cases.add(caseMap(rows, clock.instant()));
                    }
                }
            }
            boolean more = cases.size() > query.limit();
            if (more) {
                cases.remove(cases.size() - 1);
            }
            String next = more ? encodeCursor(revision, offset + query.limit()) : null;
            return new CasePage(revision, snapshot(connection, tenantId), cases, next);
        } catch (SQLException exception) {
            throw readFailure(exception);
        }
    }

    @Override
    public Optional<Map<String, Object>> caseDetail(String caseId) {
        if (caseId == null) {
            return Optional.empty();
        }
        try (Connection connection = connections.open()) {
            UUID tenantId = tenantId(connection);
            if (tenantId == null) {
                return Optional.empty();
            }
            Map<String, Object> output;
            UUID internalCaseId;
            try (PreparedStatement statement = connection.prepareStatement(
                    caseSelect() + " WHERE c.tenant_id = ? AND c.public_id = ?")) {
                statement.setObject(1, tenantId);
                statement.setString(2, caseId);
                try (ResultSet rows = statement.executeQuery()) {
                    if (!rows.next()) {
                        return Optional.empty();
                    }
                    internalCaseId = rows.getObject("internal_case_id", UUID.class);
                    output = caseMap(rows, clock.instant());
                    output.put("description", rows.getString("description_current"));
                }
            }
            output.put("exposures", exposures(connection, tenantId, internalCaseId));
            output.put("auditEvents", auditEvents(connection, tenantId, internalCaseId, caseId));
            return Optional.of(output);
        } catch (SQLException exception) {
            throw readFailure(exception);
        }
    }

    @Override
    public boolean isMaterialized(UUID importId) {
        try (Connection connection = connections.open()) {
            UUID tenantId = tenantId(connection);
            if (tenantId == null) {
                return false;
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT 1 FROM rbvm.domain_materialization
                    WHERE tenant_id = ? AND import_id = ?
                    """)) {
                statement.setObject(1, tenantId);
                statement.setObject(2, importId);
                try (ResultSet rows = statement.executeQuery()) {
                    return rows.next();
                }
            }
        } catch (SQLException exception) {
            throw readFailure(exception);
        }
    }

    @Override
    public DomainMaterializationResult materialize(UUID importId, Path csvPath, String sourceProfileId,
                                                   String contractId)
            throws IOException {
        throw new UnsupportedOperationException("PostgreSQL read catalog does not materialize CSV files");
    }

    @Override
    public PreparedCaseAction prepareCaseAction(long sequence, String caseId,
            CaseActionCommand command, String idempotencyKey, String actorId,
            String actorAssurance, Instant occurredAt) {
        throw new UnsupportedOperationException("PostgreSQL read catalog does not prepare actions");
    }

    @Override
    public Map<String, Object> applyCaseEvent(CaseAuditEvent event) {
        throw new UnsupportedOperationException("PostgreSQL read catalog does not apply actions");
    }

    private static String caseSelect() {
        return """
                SELECT c.id AS internal_case_id, c.public_id AS case_id,
                       a.public_id AS asset_id, a.observed_name AS asset_name,
                       a.os_name_raw AS os_name, sp.external_key AS source_profile_id,
                       v.cve_id, v.description_current, c.status, c.current_severity,
                       v.cvss_version, v.cvss_base_score, v.cvss_vector,
                       v.epss_probability, v.epss_percentile, v.known_exploited,
                       v.kev_date_added, v.kev_due_date, v.intelligence_observed_at,
                       v.intelligence_source_references, v.priority_tier,
                       c.first_observed_at, c.last_observed_at,
                       (SELECT count(*) FROM rbvm.exposure e
                          WHERE e.tenant_id = c.tenant_id AND e.case_id = c.id) AS exposure_count,
                       c.workflow_version, c.risk_accepted_until, c.decision_reason,
                       c.decision_evidence, c.last_workflow_at, c.closure_policy
                FROM rbvm.vulnerability_case c
                JOIN rbvm.asset a ON a.tenant_id = c.tenant_id AND a.id = c.asset_id
                JOIN rbvm.source_profile sp
                  ON sp.tenant_id = c.tenant_id AND sp.id = c.source_profile_id
                JOIN rbvm.vulnerability v ON v.id = c.vulnerability_id
                """;
    }

    private static String caseOrder() {
        return """
                 ORDER BY CASE c.current_severity
                     WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2
                     WHEN 'LOW' THEN 1 ELSE 0 END DESC,
                     c.last_observed_at DESC, c.public_id
                """;
    }

    private static void appendFilters(StringBuilder sql, List<Object> parameters, CaseQuery query) {
        appendEnumFilter(sql, parameters, "c.current_severity", query.severities());
        appendEnumFilter(sql, parameters, "c.status", query.statuses());
        appendEnumFilter(sql, parameters, "v.priority_tier", query.priorityTiers());
        if (query.knownExploited() != null) {
            sql.append(" AND v.known_exploited = ?");
            parameters.add(query.knownExploited());
        }
        if (query.cveContains() != null) {
            sql.append(" AND v.cve_id LIKE ?");
            parameters.add('%' + query.cveContains().toUpperCase(Locale.ROOT) + '%');
        }
        if (query.assetContains() != null) {
            sql.append(" AND (lower(a.observed_name) LIKE ? OR a.normalized_observed_name LIKE ?)");
            String value = '%' + query.assetContains().toLowerCase(Locale.ROOT) + '%';
            parameters.add(value);
            parameters.add(value);
        }
    }

    private static void appendEnumFilter(StringBuilder sql, List<Object> parameters,
            String column, java.util.Set<? extends Enum<?>> values) {
        if (values.isEmpty()) {
            return;
        }
        sql.append(" AND ").append(column).append(" IN (");
        boolean first = true;
        for (Enum<?> value : values) {
            if (!first) {
                sql.append(',');
            }
            sql.append('?');
            parameters.add(value.name());
            first = false;
        }
        sql.append(')');
    }

    private static Map<String, Object> caseMap(ResultSet rows, Instant now) throws SQLException {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("caseId", rows.getString("case_id").trim());
        output.put("assetId", rows.getString("asset_id").trim());
        output.put("assetName", rows.getString("asset_name"));
        output.put("osName", rows.getString("os_name"));
        output.put("sourceProfileId", rows.getString("source_profile_id"));
        output.put("cveId", rows.getString("cve_id"));
        String status = rows.getString("status");
        output.put("status", status);
        output.put("currentSeverity", rows.getString("current_severity"));
        output.put("firstObservedAt", instant(rows, "first_observed_at").toString());
        output.put("lastObservedAt", instant(rows, "last_observed_at").toString());
        output.put("exposureCount", rows.getLong("exposure_count"));
        output.put("workflowVersion", rows.getLong("workflow_version"));
        Instant acceptedUntil = optionalInstant(rows, "risk_accepted_until");
        output.put("riskAcceptedUntil", acceptedUntil == null ? null : acceptedUntil.toString());
        output.put("riskAcceptanceExpired", status.equals(CaseStatus.ACCEPTED_RISK.name())
                && acceptedUntil != null && !acceptedUntil.isAfter(now));
        output.put("decisionReason", rows.getString("decision_reason"));
        output.put("decisionEvidence", rows.getString("decision_evidence"));
        Instant workflowAt = optionalInstant(rows, "last_workflow_at");
        output.put("lastWorkflowAt", workflowAt == null ? null : workflowAt.toString());
        output.put("closurePolicy", rows.getString("closure_policy"));
        Instant intelligenceAt = optionalInstant(rows, "intelligence_observed_at");
        if (intelligenceAt == null) {
            output.put("vulnerabilityIntelligence", null);
        } else {
            Map<String, Object> intelligence = new LinkedHashMap<>();
            intelligence.put("priorityTier", rows.getString("priority_tier"));
            intelligence.put("cvssVersion", rows.getString("cvss_version"));
            intelligence.put("cvssBaseScore", optionalDouble(rows, "cvss_base_score"));
            intelligence.put("cvssVector", rows.getString("cvss_vector"));
            intelligence.put("epssProbability", optionalDouble(rows, "epss_probability"));
            intelligence.put("epssPercentile", optionalDouble(rows, "epss_percentile"));
            Object exploited = rows.getObject("known_exploited");
            intelligence.put("knownExploited", exploited == null ? null : rows.getBoolean("known_exploited"));
            Object added = rows.getObject("kev_date_added");
            Object due = rows.getObject("kev_due_date");
            intelligence.put("kevDateAdded", added == null ? null : added.toString());
            intelligence.put("kevDueDate", due == null ? null : due.toString());
            intelligence.put("observedAt", intelligenceAt.toString());
            intelligence.put("sourceReferences", rows.getString("intelligence_source_references"));
            output.put("vulnerabilityIntelligence", intelligence);
        }
        return output;
    }

    private static Double optionalDouble(ResultSet rows, String column) throws SQLException {
        double value = rows.getDouble(column);
        return rows.wasNull() ? null : value;
    }

    private static List<Map<String, Object>> exposures(Connection connection, UUID tenantId,
            UUID caseId) throws SQLException {
        List<Map<String, Object>> output = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.public_id AS exposure_id, a.public_id AS asset_id,
                       ac.public_id AS component_id, v.cve_id,
                       ac.observed_product_name AS product, ac.version_status,
                       ac.package_version, ac.package_architecture,
                       e.status, e.current_severity, e.current_severity_observed_at,
                       e.first_observed_at, e.last_observed_at, e.observation_count,
                       e.severity_changed, e.timestamp_severity_conflict, e.closure_policy,
                       e.lifecycle_observed_at, e.resolved_at
                FROM rbvm.exposure e
                JOIN rbvm.asset a ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
                JOIN rbvm.asset_component ac
                  ON ac.tenant_id = e.tenant_id AND ac.id = e.component_id
                JOIN rbvm.vulnerability v ON v.id = e.vulnerability_id
                WHERE e.tenant_id = ? AND e.case_id = ?
                ORDER BY CASE e.current_severity
                    WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1 ELSE 0 END DESC,
                    e.last_observed_at DESC, e.public_id
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, caseId);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("exposureId", rows.getString("exposure_id").trim());
                    item.put("assetId", rows.getString("asset_id").trim());
                    item.put("componentId", rows.getString("component_id").trim());
                    item.put("cveId", rows.getString("cve_id"));
                    item.put("product", rows.getString("product"));
                    item.put("versionStatus", rows.getString("version_status"));
                    item.put("packageVersion", rows.getString("package_version"));
                    item.put("packageArchitecture", rows.getString("package_architecture"));
                    item.put("status", rows.getString("status"));
                    item.put("currentSeverity", rows.getString("current_severity"));
                    item.put("currentSeverityObservedAt",
                            instant(rows, "current_severity_observed_at").toString());
                    item.put("firstObservedAt", instant(rows, "first_observed_at").toString());
                    item.put("lastObservedAt", instant(rows, "last_observed_at").toString());
                    item.put("observationCount", rows.getLong("observation_count"));
                    item.put("severityChanged", rows.getBoolean("severity_changed"));
                    item.put("timestampSeverityConflict",
                            rows.getBoolean("timestamp_severity_conflict"));
                    item.put("closurePolicy", rows.getString("closure_policy"));
                    item.put("lifecycleObservedAt",
                            instant(rows, "lifecycle_observed_at").toString());
                    Instant resolved = optionalInstant(rows, "resolved_at");
                    item.put("resolvedAt", resolved == null ? null : resolved.toString());
                    output.add(item);
                }
            }
        }
        return output;
    }

    private static List<Map<String, Object>> auditEvents(Connection connection, UUID tenantId,
            UUID caseId, String casePublicId) throws SQLException {
        List<Map<String, Object>> output = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT source_sequence, public_id, case_version, action_type, from_status,
                       to_status, reason, expires_at, evidence_reference, actor_id,
                       actor_assurance, occurred_at
                FROM rbvm.case_audit_event
                WHERE tenant_id = ? AND case_id = ?
                ORDER BY source_sequence
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, caseId);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("sequence", rows.getLong("source_sequence"));
                    item.put("eventId", rows.getString("public_id").trim());
                    item.put("caseId", casePublicId);
                    item.put("caseVersion", rows.getLong("case_version"));
                    item.put("action", rows.getString("action_type"));
                    item.put("fromStatus", rows.getString("from_status"));
                    item.put("toStatus", rows.getString("to_status"));
                    item.put("reason", rows.getString("reason"));
                    Instant expires = optionalInstant(rows, "expires_at");
                    item.put("expiresAt", expires == null ? null : expires.toString());
                    item.put("evidenceReference", rows.getString("evidence_reference"));
                    item.put("actorId", rows.getString("actor_id"));
                    item.put("actorAssurance", rows.getString("actor_assurance"));
                    item.put("occurredAt", instant(rows, "occurred_at").toString());
                    output.add(item);
                }
            }
        }
        return output;
    }

    private static CatalogSnapshot snapshot(Connection connection, UUID tenantId)
            throws SQLException {
        long materialized = count(connection,
                "SELECT count(*) FROM rbvm.domain_materialization WHERE tenant_id = ?", tenantId);
        long observations = count(connection,
                "SELECT count(*) FROM rbvm.observation WHERE tenant_id = ?", tenantId);
        long links = count(connection,
                "SELECT count(*) FROM rbvm.import_observation WHERE tenant_id = ?", tenantId);
        long assets = count(connection, "SELECT count(*) FROM rbvm.asset WHERE tenant_id = ?", tenantId);
        long vulnerabilities = count(connection, """
                SELECT count(DISTINCT vulnerability_id) FROM rbvm.observation WHERE tenant_id = ?
                """, tenantId);
        long components = count(connection,
                "SELECT count(*) FROM rbvm.asset_component WHERE tenant_id = ?", tenantId);
        long exposures = count(connection,
                "SELECT count(*) FROM rbvm.exposure WHERE tenant_id = ?", tenantId);
        long cases = count(connection,
                "SELECT count(*) FROM rbvm.vulnerability_case WHERE tenant_id = ?", tenantId);
        long openCases = count(connection, """
                SELECT count(*) FROM rbvm.vulnerability_case WHERE tenant_id = ? AND status = 'OPEN'
                """, tenantId);
        long sourceResolvedCases = count(connection, """
                SELECT count(*) FROM rbvm.vulnerability_case
                WHERE tenant_id = ? AND status = 'SOURCE_RESOLVED'
                """, tenantId);
        long changed = count(connection, """
                SELECT count(*) FROM rbvm.exposure WHERE tenant_id = ? AND severity_changed
                """, tenantId);
        long conflicts = count(connection, """
                SELECT count(*) FROM rbvm.exposure
                WHERE tenant_id = ? AND timestamp_severity_conflict
                """, tenantId);
        Map<String, Long> severities = enumCounts(CsvSeverity.values());
        fillCounts(connection, tenantId, "current_severity", severities);
        Map<String, Long> statuses = enumCounts(CaseStatus.values());
        fillCounts(connection, tenantId, "status", statuses);
        return new CatalogSnapshot(materialized, observations, links, assets, vulnerabilities,
                components, exposures, cases, openCases, sourceResolvedCases, changed, conflicts,
                severities, statuses);
    }

    private static void fillCounts(Connection connection, UUID tenantId, String column,
            Map<String, Long> output) throws SQLException {
        String sql = "SELECT " + column + ", count(*) FROM rbvm.vulnerability_case "
                + "WHERE tenant_id = ? GROUP BY " + column;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, tenantId);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    output.put(rows.getString(1), rows.getLong(2));
                }
            }
        }
    }

    private static Map<String, Long> enumCounts(Enum<?>[] values) {
        Map<String, Long> output = new LinkedHashMap<>();
        for (Enum<?> value : values) {
            output.put(value.name(), 0L);
        }
        return output;
    }

    private static CatalogSnapshot emptySnapshot() {
        return new CatalogSnapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                enumCounts(CsvSeverity.values()), enumCounts(CaseStatus.values()));
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

    private static long revision(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT revision FROM rbvm.catalog_state WHERE tenant_id = ?")) {
            statement.setObject(1, tenantId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getLong(1) : 0;
            }
        }
    }

    private static long count(Connection connection, String sql, UUID tenantId)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, tenantId);
            try (ResultSet rows = statement.executeQuery()) {
                rows.next();
                return rows.getLong(1);
            }
        }
    }

    private static void bind(PreparedStatement statement, List<Object> parameters)
            throws SQLException {
        for (int index = 0; index < parameters.size(); index++) {
            statement.setObject(index + 1, parameters.get(index));
        }
    }

    private static Instant instant(ResultSet rows, String column) throws SQLException {
        return rows.getTimestamp(column).toInstant();
    }

    private static Instant optionalInstant(ResultSet rows, String column) throws SQLException {
        Timestamp timestamp = rows.getTimestamp(column);
        return timestamp == null ? null : timestamp.toInstant();
    }

    private static int decodeCursor(String cursor, long revision) {
        if (cursor == null) {
            return 0;
        }
        try {
            String decoded = new String(Base64.getUrlDecoder().decode(cursor),
                    StandardCharsets.UTF_8);
            String[] parts = decoded.split(":", -1);
            if (parts.length != 2) {
                throw new IllegalArgumentException("invalid parts");
            }
            long cursorRevision = Long.parseLong(parts[0]);
            int offset = Integer.parseInt(parts[1]);
            if (cursorRevision != revision) {
                throw new StaleCaseCursorException(
                        "Case catalog changed from revision " + cursorRevision + " to " + revision);
            }
            if (offset < 0) {
                throw new IllegalArgumentException("negative offset");
            }
            return offset;
        } catch (StaleCaseCursorException exception) {
            throw exception;
        } catch (IllegalArgumentException exception) {
            throw new InvalidCaseActionException("cursor is invalid");
        }
    }

    private static String encodeCursor(long revision, int offset) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                (revision + ":" + offset).getBytes(StandardCharsets.UTF_8));
    }

    private static IllegalStateException readFailure(SQLException exception) {
        return new IllegalStateException("PostgreSQL catalog read failed", exception);
    }
}
