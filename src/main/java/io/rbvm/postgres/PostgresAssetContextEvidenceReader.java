package io.rbvm.postgres;

import java.io.IOException;
import java.sql.Connection;
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

/** PostgreSQL current-evidence reader for independent organizational asset-context evidence. */
public final class PostgresAssetContextEvidenceReader implements AssetContextEvidenceReader {
    private static final String TENANT_KEY = "local";
    private final JdbcConnectionFactory connections;

    public PostgresAssetContextEvidenceReader(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    @Override
    public Map<String, Object> currentEvidence(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String contextSource
    ) throws IOException {
        if (limit < 1 || limit > 500) {
            throw new IllegalArgumentException("limit must be between 1 and 500");
        }
        String normalizedAsset = normalizeOptional(assetPrefix, 160, "asset");
        String normalizedProfile = normalizeProfile(sourceProfileKey);
        String normalizedContextSource = normalizeOptional(contextSource, 256, "contextSource");

        List<Map<String, Object>> items = new ArrayList<>();
        String sql = """
                SELECT
                    e.source_profile_key,
                    e.asset_identity_basis,
                    e.asset_name_observed,
                    e.asset_source_id,
                    e.environment,
                    e.business_service,
                    e.business_owner,
                    e.business_criticality,
                    e.context_source,
                    e.source_sha256,
                    e.observed_at,
                    e.evidence_ingested_at,
                    e.snapshot_ingested_at
                FROM rbvm.current_asset_context_evidence e
                JOIN rbvm.tenant t
                  ON t.id = e.tenant_id
                WHERE t.tenant_key = ?
                  AND (? IS NULL OR lower(e.asset_name_observed) LIKE ?
                       OR lower(COALESCE(e.asset_source_id, '')) LIKE ?)
                  AND (? IS NULL OR e.source_profile_key = ?)
                  AND (? IS NULL OR e.context_source = ?)
                ORDER BY e.observed_at DESC, e.asset_name_observed,
                         e.source_profile_key, e.context_source
                LIMIT ?
                """;
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, TENANT_KEY);
            if (normalizedAsset == null) {
                statement.setString(2, null);
                statement.setString(3, null);
                statement.setString(4, null);
            } else {
                statement.setString(2, normalizedAsset);
                statement.setString(3, normalizedAsset + "%");
                statement.setString(4, normalizedAsset + "%");
            }
            statement.setString(5, normalizedProfile);
            statement.setString(6, normalizedProfile);
            statement.setString(7, normalizedContextSource);
            statement.setString(8, normalizedContextSource);
            statement.setInt(9, limit);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("sourceProfileKey", rows.getString(1));
                    item.put("assetIdentityBasis", rows.getString(2));
                    item.put("assetName", rows.getString(3));
                    item.put("assetSourceId", rows.getString(4));
                    item.put("environment", rows.getString(5));
                    item.put("businessService", rows.getString(6));
                    item.put("businessOwner", rows.getString(7));
                    item.put("businessCriticality", rows.getString(8));
                    item.put("contextSource", rows.getString(9));
                    item.put("contextSourceSha256", rows.getString(10).trim());
                    item.put("contextObservedAt", rows.getTimestamp(11).toInstant().toString());
                    item.put("evidenceIngestedAt", rows.getTimestamp(12).toInstant().toString());
                    item.put("snapshotIngestedAt", rows.getTimestamp(13).toInstant().toString());
                    items.add(Collections.unmodifiableMap(new LinkedHashMap<>(item)));
                }
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("Could not read PostgreSQL asset context evidence", exception);
        }

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("semantics", "CURRENT_PER_SOURCE_ASSET_ORGANIZATIONAL_CONTEXT_EVIDENCE");
        output.put("limit", limit);
        output.put("assetPrefix", normalizedAsset);
        output.put("sourceProfileKey", normalizedProfile);
        output.put("contextSource", normalizedContextSource);
        output.put("count", items.size());
        output.put("items", List.copyOf(items));
        return Collections.unmodifiableMap(output);
    }

    private static String normalizeProfile(String value) {
        String normalized = normalizeOptional(value, 128, "sourceProfile");
        if (normalized == null) {
            return null;
        }
        if (!normalized.matches("[A-Za-z0-9._:-]+")) {
            throw new IllegalArgumentException("sourceProfile contains unsupported characters");
        }
        return normalized;
    }

    private static String normalizeOptional(String value, int maximumLength, String field) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.length() > maximumLength || normalized.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " is invalid or too long");
        }
        if (field.equals("asset")) {
            normalized = normalized.toLowerCase(Locale.ROOT);
        }
        return normalized;
    }
}
