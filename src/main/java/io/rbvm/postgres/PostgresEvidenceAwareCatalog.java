package io.rbvm.postgres;

import io.rbvm.domain.CaseActionCommand;
import io.rbvm.domain.CaseAuditEvent;
import io.rbvm.domain.CasePage;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.CatalogSnapshot;
import io.rbvm.domain.DomainCatalog;
import io.rbvm.domain.DomainMaterializationResult;
import io.rbvm.domain.PreparedCaseAction;

import java.io.IOException;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Current finding read projection backed by the independent CVSS, EPSS, and CISA KEV evidence
 * stores introduced in PostgreSQL V10-V12.
 *
 * <p>The legacy intelligence columns on {@code rbvm.vulnerability} remain available for historical
 * import compatibility, but they are not current evidence authority once this catalog is enabled.
 * Multiple current source rows are surfaced as AMBIGUOUS rather than silently choosing a source.</p>
 */
public final class PostgresEvidenceAwareCatalog implements DomainCatalog {
    private static final String TENANT_KEY = "local";

    private final DomainCatalog delegate;
    private final JdbcConnectionFactory connections;

    public PostgresEvidenceAwareCatalog(DomainCatalog delegate, JdbcConnectionFactory connections) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.connections = Objects.requireNonNull(connections, "connections");
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
        return delegate.snapshot();
    }

    @Override
    public CasePage queryCases(CaseQuery query) {
        Objects.requireNonNull(query, "query");
        CaseQuery sourceQuery = query.knownExploited() == null ? query : new CaseQuery(
                query.limit(),
                query.cursor(),
                query.severities(),
                query.statuses(),
                query.cveContains(),
                query.assetContains(),
                query.priorityTiers(),
                null
        );
        CasePage page = delegate.queryCases(sourceQuery);
        List<Map<String, Object>> cases = augment(page.cases());
        if (query.knownExploited() != null) {
            boolean expected = query.knownExploited();
            cases = cases.stream()
                    .filter(item -> {
                        Object value = intelligence(item).get("knownExploited");
                        return value instanceof Boolean actual && actual == expected;
                    })
                    .toList();
        }
        return new CasePage(page.catalogRevision(), page.summary(), cases, page.nextCursor());
    }

    @Override
    public Optional<Map<String, Object>> caseDetail(String caseId) {
        Optional<Map<String, Object>> detail = delegate.caseDetail(caseId);
        return detail.map(item -> augment(List.of(item)).get(0));
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

    private List<Map<String, Object>> augment(List<Map<String, Object>> input) {
        if (input.isEmpty()) {
            return input;
        }
        Set<String> cves = new LinkedHashSet<>();
        for (Map<String, Object> item : input) {
            Object value = item.get("cveId");
            if (value instanceof String cve && !cve.isBlank()) {
                cves.add(cve.trim().toUpperCase());
            }
        }
        if (cves.isEmpty()) {
            return input;
        }

        Map<String, EvidenceBundle> evidence = readEvidence(cves);
        List<Map<String, Object>> output = new ArrayList<>(input.size());
        for (Map<String, Object> item : input) {
            Map<String, Object> copy = new LinkedHashMap<>(item);
            String cve = String.valueOf(item.get("cveId")).trim().toUpperCase();
            EvidenceBundle bundle = evidence.getOrDefault(cve, new EvidenceBundle());
            Object legacyPriority = intelligence(item).get("priorityTier");
            copy.put("vulnerabilityIntelligence", bundle.toMap(legacyPriority));
            output.add(copy);
        }
        return output;
    }

    private Map<String, EvidenceBundle> readEvidence(Set<String> cves) {
        Map<String, EvidenceBundle> output = new LinkedHashMap<>();
        for (String cve : cves) {
            output.put(cve, new EvidenceBundle());
        }
        try (Connection connection = connections.open()) {
            UUID tenantId = tenantId(connection);
            if (tenantId == null) {
                return output;
            }
            readCvss(connection, tenantId, cves, output);
            readEpss(connection, tenantId, cves, output);
            readKev(connection, tenantId, cves, output);
            return output;
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("PostgreSQL dedicated intelligence read failed", exception);
        }
    }

    private static void readCvss(
            Connection connection,
            UUID tenantId,
            Set<String> cves,
            Map<String, EvidenceBundle> output
    ) throws SQLException {
        String sql = """
                SELECT v.cve_id, e.cvss_version, e.base_score, e.vector,
                       e.cvss_source, e.observed_at, e.evidence_sha256
                FROM rbvm.current_cvss_v31_base_evidence e
                JOIN rbvm.vulnerability v ON v.id = e.vulnerability_id
                WHERE e.tenant_id = ? AND v.cve_id IN (%s)
                ORDER BY v.cve_id, e.cvss_source
                """.formatted(placeholders(cves.size()));
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            bindCves(statement, tenantId, cves);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Map<String, Object> value = new LinkedHashMap<>();
                    value.put("cvssVersion", rows.getString("cvss_version"));
                    value.put("cvssBaseScore", rows.getBigDecimal("base_score").doubleValue());
                    value.put("cvssVector", rows.getString("vector"));
                    value.put("cvssSource", rows.getString("cvss_source"));
                    value.put("cvssObservedAt", rows.getTimestamp("observed_at").toInstant().toString());
                    value.put("cvssEvidenceSha256", rows.getString("evidence_sha256").trim());
                    output.get(rows.getString("cve_id")).cvss.add(value);
                }
            }
        }
    }

    private static void readEpss(
            Connection connection,
            UUID tenantId,
            Set<String> cves,
            Map<String, EvidenceBundle> output
    ) throws SQLException {
        String sql = """
                SELECT v.cve_id, e.epss_probability, e.epss_percentile,
                       e.model_version, e.score_date, e.epss_source,
                       e.source_sha256, e.observed_at, e.evidence_sha256
                FROM rbvm.current_epss_evidence e
                JOIN rbvm.vulnerability v ON v.id = e.vulnerability_id
                WHERE e.tenant_id = ? AND v.cve_id IN (%s)
                ORDER BY v.cve_id, e.epss_source
                """.formatted(placeholders(cves.size()));
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            bindCves(statement, tenantId, cves);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Map<String, Object> value = new LinkedHashMap<>();
                    value.put("epssProbability", rows.getBigDecimal("epss_probability").doubleValue());
                    value.put("epssPercentile", rows.getBigDecimal("epss_percentile").doubleValue());
                    value.put("epssModelVersion", rows.getString("model_version"));
                    value.put("epssScoreDate", rows.getDate("score_date").toLocalDate().toString());
                    value.put("epssSource", rows.getString("epss_source"));
                    value.put("epssSourceSha256", rows.getString("source_sha256").trim());
                    value.put("epssObservedAt", rows.getTimestamp("observed_at").toInstant().toString());
                    value.put("epssEvidenceSha256", rows.getString("evidence_sha256").trim());
                    output.get(rows.getString("cve_id")).epss.add(value);
                }
            }
        }
    }

    private static void readKev(
            Connection connection,
            UUID tenantId,
            Set<String> cves,
            Map<String, EvidenceBundle> output
    ) throws SQLException {
        String sql = """
                SELECT v.cve_id, e.kev_status, e.kev_date_added, e.kev_due_date,
                       e.known_ransomware_campaign_use, e.catalog_version,
                       e.catalog_sha256, e.catalog_count, e.kev_source,
                       e.observed_at, e.evidence_sha256
                FROM rbvm.current_cisa_kev_evidence e
                JOIN rbvm.vulnerability v ON v.id = e.vulnerability_id
                WHERE e.tenant_id = ? AND v.cve_id IN (%s)
                ORDER BY v.cve_id, e.kev_source
                """.formatted(placeholders(cves.size()));
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            bindCves(statement, tenantId, cves);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Map<String, Object> value = new LinkedHashMap<>();
                    String status = rows.getString("kev_status");
                    value.put("kevStatus", status);
                    value.put("knownExploited", "LISTED".equals(status));
                    value.put("kevDateAdded", optionalDate(rows, "kev_date_added"));
                    value.put("kevDueDate", optionalDate(rows, "kev_due_date"));
                    value.put("knownRansomwareCampaignUse", rows.getString("known_ransomware_campaign_use"));
                    value.put("kevCatalogVersion", rows.getString("catalog_version"));
                    value.put("kevCatalogSha256", rows.getString("catalog_sha256").trim());
                    value.put("kevCatalogCount", rows.getInt("catalog_count"));
                    value.put("kevSource", rows.getString("kev_source"));
                    value.put("kevObservedAt", rows.getTimestamp("observed_at").toInstant().toString());
                    value.put("kevEvidenceSha256", rows.getString("evidence_sha256").trim());
                    output.get(rows.getString("cve_id")).kev.add(value);
                }
            }
        }
    }

    private static String optionalDate(ResultSet rows, String column) throws SQLException {
        java.sql.Date value = rows.getDate(column);
        return value == null ? null : value.toLocalDate().toString();
    }

    private static String placeholders(int size) {
        return String.join(",", java.util.Collections.nCopies(size, "?"));
    }

    private static void bindCves(
            PreparedStatement statement, UUID tenantId, Set<String> cves
    ) throws SQLException {
        statement.setObject(1, tenantId);
        int index = 2;
        for (String cve : cves) {
            statement.setString(index++, cve);
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

    @SuppressWarnings("unchecked")
    private static Map<String, Object> intelligence(Map<String, Object> item) {
        Object value = item.get("vulnerabilityIntelligence");
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    private static String state(int count) {
        if (count == 0) return "MISSING";
        if (count == 1) return "PRESENT";
        return "AMBIGUOUS";
    }

    private static Object one(List<Map<String, Object>> rows, String key) {
        return rows.size() == 1 ? rows.get(0).get(key) : null;
    }

    private static Instant parsedInstant(Object value) {
        return value instanceof String text ? Instant.parse(text) : null;
    }

    private static Instant latest(Instant current, Object value) {
        Instant candidate = parsedInstant(value);
        if (candidate == null) return current;
        return current == null || candidate.isAfter(current) ? candidate : current;
    }

    private static final class EvidenceBundle {
        private final List<Map<String, Object>> cvss = new ArrayList<>();
        private final List<Map<String, Object>> epss = new ArrayList<>();
        private final List<Map<String, Object>> kev = new ArrayList<>();

        private Map<String, Object> toMap(Object legacyPriority) {
            Map<String, Object> output = new LinkedHashMap<>();
            output.put("intelligenceSemantics", "DEDICATED_CURRENT_EVIDENCE_NO_HIDDEN_SOURCE_PRECEDENCE");
            output.put("priorityTier", legacyPriority);

            output.put("cvssEvidenceState", state(cvss.size()));
            output.put("cvssSourceCount", cvss.size());
            output.put("cvssVersion", one(cvss, "cvssVersion"));
            output.put("cvssBaseScore", one(cvss, "cvssBaseScore"));
            output.put("cvssVector", one(cvss, "cvssVector"));
            output.put("cvssSource", one(cvss, "cvssSource"));
            output.put("cvssObservedAt", one(cvss, "cvssObservedAt"));
            output.put("cvssEvidenceSha256", one(cvss, "cvssEvidenceSha256"));

            output.put("epssEvidenceState", state(epss.size()));
            output.put("epssSourceCount", epss.size());
            output.put("epssProbability", one(epss, "epssProbability"));
            output.put("epssPercentile", one(epss, "epssPercentile"));
            output.put("epssModelVersion", one(epss, "epssModelVersion"));
            output.put("epssScoreDate", one(epss, "epssScoreDate"));
            output.put("epssSource", one(epss, "epssSource"));
            output.put("epssSourceSha256", one(epss, "epssSourceSha256"));
            output.put("epssObservedAt", one(epss, "epssObservedAt"));
            output.put("epssEvidenceSha256", one(epss, "epssEvidenceSha256"));

            output.put("kevEvidenceState", state(kev.size()));
            output.put("kevSourceCount", kev.size());
            output.put("kevStatus", kev.isEmpty() ? "UNKNOWN" : one(kev, "kevStatus"));
            output.put("knownExploited", one(kev, "knownExploited"));
            output.put("kevDateAdded", one(kev, "kevDateAdded"));
            output.put("kevDueDate", one(kev, "kevDueDate"));
            output.put("knownRansomwareCampaignUse", one(kev, "knownRansomwareCampaignUse"));
            output.put("kevCatalogVersion", one(kev, "kevCatalogVersion"));
            output.put("kevCatalogSha256", one(kev, "kevCatalogSha256"));
            output.put("kevCatalogCount", one(kev, "kevCatalogCount"));
            output.put("kevSource", one(kev, "kevSource"));
            output.put("kevObservedAt", one(kev, "kevObservedAt"));
            output.put("kevEvidenceSha256", one(kev, "kevEvidenceSha256"));

            Instant newest = null;
            newest = latest(newest, one(cvss, "cvssObservedAt"));
            newest = latest(newest, one(epss, "epssObservedAt"));
            newest = latest(newest, one(kev, "kevObservedAt"));
            output.put("observedAt", newest == null ? null : newest.toString());
            List<String> sources = new ArrayList<>();
            for (Object source : List.of(
                    one(cvss, "cvssSource"), one(epss, "epssSource"), one(kev, "kevSource"))) {
                if (source instanceof String text && !text.isBlank() && !sources.contains(text)) {
                    sources.add(text);
                }
            }
            output.put("sourceReferences", sources.isEmpty() ? null : String.join(",", sources));
            return output;
        }
    }
}
