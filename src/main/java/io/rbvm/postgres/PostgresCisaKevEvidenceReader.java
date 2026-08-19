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

/** PostgreSQL current-evidence reader for snapshot-bound CISA KEV membership evidence. */
public final class PostgresCisaKevEvidenceReader implements CisaKevEvidenceReader {
    private static final String TENANT_KEY = "local";
    private final JdbcConnectionFactory connections;

    public PostgresCisaKevEvidenceReader(JdbcConnectionFactory connections) {
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
                    k.kev_status,
                    k.kev_date_added,
                    k.kev_due_date,
                    k.known_ransomware_campaign_use,
                    k.catalog_version,
                    k.catalog_sha256,
                    k.catalog_count,
                    k.kev_source,
                    k.observed_at,
                    k.evidence_ingested_at,
                    k.snapshot_ingested_at
                FROM rbvm.current_cisa_kev_evidence k
                JOIN rbvm.vulnerability v
                  ON v.id = k.vulnerability_id
                JOIN rbvm.tenant t
                  ON t.id = k.tenant_id
                WHERE t.tenant_key = ?
                  AND (? IS NULL OR upper(v.cve_id) LIKE ?)
                ORDER BY k.observed_at DESC, v.cve_id, k.kev_source
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
                    item.put("kevStatus", rows.getString(2));
                    item.put("kevDateAdded", rows.getDate(3) == null ? null : rows.getDate(3).toLocalDate().toString());
                    item.put("kevDueDate", rows.getDate(4) == null ? null : rows.getDate(4).toLocalDate().toString());
                    item.put("knownRansomwareCampaignUse", rows.getString(5));
                    item.put("kevCatalogVersion", rows.getString(6));
                    item.put("kevCatalogSha256", rows.getString(7).trim());
                    item.put("kevCatalogCount", rows.getInt(8));
                    item.put("kevSource", rows.getString(9));
                    item.put("kevObservedAt", rows.getTimestamp(10).toInstant().toString());
                    item.put("evidenceIngestedAt", rows.getTimestamp(11).toInstant().toString());
                    item.put("snapshotIngestedAt", rows.getTimestamp(12).toInstant().toString());
                    items.add(Map.copyOf(item));
                }
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("Could not read PostgreSQL CISA KEV evidence", exception);
        }

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("semantics", "CURRENT_PER_SOURCE_CISA_KEV_SNAPSHOT_MEMBERSHIP_EVIDENCE");
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
