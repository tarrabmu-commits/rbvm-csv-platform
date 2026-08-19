package io.rbvm.postgres;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/** PostgreSQL current-evidence reader for the independent CVSS v3.1 Base model. */
public final class PostgresCvssV31EvidenceReader implements CvssV31EvidenceReader {
    private static final String TENANT_KEY = "local";
    private final JdbcConnectionFactory connections;

    public PostgresCvssV31EvidenceReader(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    @Override
    public Map<String, Object> currentEvidence(int limit, String cvePrefix) throws IOException {
        if (limit < 1 || limit > 500) {
            throw new IllegalArgumentException("limit must be between 1 and 500");
        }
        String normalizedPrefix = normalizePrefix(cvePrefix);
        List<Map<String, Object>> items = new ArrayList<>();
        String sql = """
                SELECT
                    v.cve_id,
                    c.cvss_version,
                    c.base_score,
                    c.vector,
                    c.cvss_source,
                    c.observed_at,
                    c.ingested_at
                FROM rbvm.current_cvss_v31_base_evidence c
                JOIN rbvm.vulnerability v
                  ON v.tenant_id = c.tenant_id
                 AND v.id = c.vulnerability_id
                JOIN rbvm.tenant t
                  ON t.id = c.tenant_id
                WHERE t.tenant_key = ?
                  AND (? IS NULL OR upper(v.cve_id) LIKE ?)
                ORDER BY c.observed_at DESC, v.cve_id, c.cvss_source
                LIMIT ?
                """;
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, TENANT_KEY);
            if (normalizedPrefix == null) {
                statement.setString(2, null);
                statement.setString(3, null);
            } else {
                statement.setString(2, normalizedPrefix);
                statement.setString(3, normalizedPrefix + "%");
            }
            statement.setInt(4, limit);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("cveId", rows.getString(1));
                    item.put("cvssVersion", rows.getString(2));
                    item.put("cvssBaseScore", rows.getBigDecimal(3));
                    item.put("cvssVector", rows.getString(4));
                    item.put("cvssSource", rows.getString(5));
                    item.put("cvssObservedAt", rows.getTimestamp(6).toInstant().toString());
                    item.put("ingestedAt", rows.getTimestamp(7).toInstant().toString());
                    items.add(Map.copyOf(item));
                }
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("Could not read PostgreSQL CVSS v3.1 evidence", exception);
        }

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("semantics", "CURRENT_PER_SOURCE_CVSS_V31_BASE_EVIDENCE");
        output.put("limit", limit);
        output.put("cvePrefix", normalizedPrefix);
        output.put("count", items.size());
        output.put("items", List.copyOf(items));
        return Map.copyOf(output);
    }

    private static String normalizePrefix(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        if (normalized.length() > 32 || !normalized.matches("CVE-[0-9A-Z-]+")) {
            throw new IllegalArgumentException("cve must be a CVE identifier or CVE prefix");
        }
        return normalized;
    }
}
