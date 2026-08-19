package io.rbvm.postgres;

import java.io.IOException;
import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/** PostgreSQL current-evidence reader for independent FIRST EPSS probability evidence. */
public final class PostgresEpssEvidenceReader implements EpssEvidenceReader {
    private static final String TENANT_KEY = "local";
    private final JdbcConnectionFactory connections;

    public PostgresEpssEvidenceReader(JdbcConnectionFactory connections) {
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
                    e.epss_probability,
                    e.epss_percentile,
                    e.model_version,
                    e.score_date,
                    e.epss_source,
                    e.source_sha256,
                    e.observed_at,
                    e.evidence_ingested_at,
                    e.snapshot_ingested_at
                FROM rbvm.current_epss_evidence e
                JOIN rbvm.vulnerability v
                  ON v.id = e.vulnerability_id
                JOIN rbvm.tenant t
                  ON t.id = e.tenant_id
                WHERE t.tenant_key = ?
                  AND (? IS NULL OR upper(v.cve_id) LIKE ?)
                ORDER BY e.score_date DESC, e.observed_at DESC, v.cve_id, e.epss_source
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
                    BigDecimal probability = rows.getBigDecimal(2);
                    BigDecimal percentile = rows.getBigDecimal(3);
                    Date scoreDate = rows.getDate(5);
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("cveId", rows.getString(1));
                    item.put("epssProbability", probability == null ? null : probability.doubleValue());
                    item.put("epssPercentile", percentile == null ? null : percentile.doubleValue());
                    item.put("epssModelVersion", rows.getString(4));
                    item.put("epssScoreDate", scoreDate == null ? null : scoreDate.toLocalDate().toString());
                    item.put("epssSource", rows.getString(6));
                    item.put("epssSourceSha256", rows.getString(7).trim());
                    item.put("epssObservedAt", rows.getTimestamp(8).toInstant().toString());
                    item.put("evidenceIngestedAt", rows.getTimestamp(9).toInstant().toString());
                    item.put("snapshotIngestedAt", rows.getTimestamp(10).toInstant().toString());
                    items.add(Collections.unmodifiableMap(new LinkedHashMap<>(item)));
                }
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("Could not read PostgreSQL EPSS evidence", exception);
        }

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("semantics", "CURRENT_PER_SOURCE_EPSS_EXPLOITATION_PROBABILITY_EVIDENCE");
        output.put("limit", limit);
        output.put("cvePrefix", normalizedPrefix);
        output.put("count", items.size());
        output.put("items", List.copyOf(items));
        return Collections.unmodifiableMap(output);
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
