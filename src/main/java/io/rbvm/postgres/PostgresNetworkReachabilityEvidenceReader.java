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

/** PostgreSQL current-evidence reader for independent scoped network reachability evidence. */
public final class PostgresNetworkReachabilityEvidenceReader
        implements NetworkReachabilityEvidenceReader {
    private static final String TENANT_KEY = "local";
    private final JdbcConnectionFactory connections;

    public PostgresNetworkReachabilityEvidenceReader(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    @Override
    public Map<String, Object> currentEvidence(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String evidenceSource,
            String originScope,
            String reachabilityStatus
    ) throws IOException {
        if (limit < 1 || limit > 500) {
            throw new IllegalArgumentException("limit must be between 1 and 500");
        }
        String normalizedAsset = normalizeOptional(assetPrefix, 160, "asset", true);
        String normalizedProfile = normalizeProfile(sourceProfileKey);
        String normalizedSource = normalizeOptional(evidenceSource, 256, "evidenceSource", false);
        String normalizedOrigin = normalizeEnum(
                originScope,
                "originScope",
                SetValues.ORIGIN_SCOPES
        );
        String normalizedStatus = normalizeEnum(
                reachabilityStatus,
                "reachabilityStatus",
                SetValues.REACHABILITY_STATUSES
        );

        List<Map<String, Object>> items = new ArrayList<>();
        String sql = """
                SELECT
                    e.source_profile_key,
                    e.asset_identity_basis,
                    e.asset_name_observed,
                    e.asset_source_id,
                    e.origin_scope,
                    e.origin_label,
                    e.transport_protocol,
                    e.target_port,
                    e.target_service,
                    e.reachability_status,
                    e.reachability_method,
                    e.evidence_source,
                    e.source_sha256,
                    e.observed_at,
                    e.evidence_ingested_at,
                    e.snapshot_ingested_at
                FROM rbvm.current_network_reachability_evidence e
                JOIN rbvm.tenant t
                  ON t.id = e.tenant_id
                WHERE t.tenant_key = ?
                  AND (? IS NULL OR lower(e.asset_name_observed) LIKE ?
                       OR lower(COALESCE(e.asset_source_id, '')) LIKE ?)
                  AND (? IS NULL OR e.source_profile_key = ?)
                  AND (? IS NULL OR e.evidence_source = ?)
                  AND (? IS NULL OR e.origin_scope = ?)
                  AND (? IS NULL OR e.reachability_status = ?)
                ORDER BY e.observed_at DESC,
                         e.asset_name_observed,
                         e.evidence_source,
                         e.origin_scope,
                         e.origin_label,
                         e.transport_protocol,
                         COALESCE(e.target_port, 0)
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
            statement.setString(7, normalizedSource);
            statement.setString(8, normalizedSource);
            statement.setString(9, normalizedOrigin);
            statement.setString(10, normalizedOrigin);
            statement.setString(11, normalizedStatus);
            statement.setString(12, normalizedStatus);
            statement.setInt(13, limit);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("sourceProfileKey", rows.getString(1));
                    item.put("assetIdentityBasis", rows.getString(2));
                    item.put("assetName", rows.getString(3));
                    item.put("assetSourceId", rows.getString(4));
                    item.put("originScope", rows.getString(5));
                    item.put("originLabel", rows.getString(6));
                    item.put("transportProtocol", rows.getString(7));
                    Object targetPort = rows.getObject(8);
                    item.put("targetPort", targetPort == null ? null : ((Number) targetPort).intValue());
                    item.put("targetService", rows.getString(9));
                    item.put("reachabilityStatus", rows.getString(10));
                    item.put("reachabilityMethod", rows.getString(11));
                    item.put("evidenceSource", rows.getString(12));
                    item.put("evidenceSourceSha256", rows.getString(13).trim());
                    item.put("evidenceObservedAt", rows.getTimestamp(14).toInstant().toString());
                    item.put("evidenceIngestedAt", rows.getTimestamp(15).toInstant().toString());
                    item.put("snapshotIngestedAt", rows.getTimestamp(16).toInstant().toString());
                    items.add(Collections.unmodifiableMap(new LinkedHashMap<>(item)));
                }
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL network reachability evidence",
                    exception
            );
        }

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("semantics", "CURRENT_PER_SOURCE_SCOPED_NETWORK_REACHABILITY_EVIDENCE");
        output.put("limit", limit);
        output.put("assetPrefix", normalizedAsset);
        output.put("sourceProfileKey", normalizedProfile);
        output.put("evidenceSource", normalizedSource);
        output.put("originScope", normalizedOrigin);
        output.put("reachabilityStatus", normalizedStatus);
        output.put("count", items.size());
        output.put("items", List.copyOf(items));
        return Collections.unmodifiableMap(output);
    }

    private static String normalizeProfile(String value) {
        String normalized = normalizeOptional(value, 128, "sourceProfile", false);
        if (normalized == null) {
            return null;
        }
        if (!normalized.matches("[A-Za-z0-9._:-]+")) {
            throw new IllegalArgumentException("sourceProfile contains unsupported characters");
        }
        return normalized;
    }

    private static String normalizeEnum(String value, String field, java.util.Set<String> allowed) {
        String normalized = normalizeOptional(value, 64, field, false);
        if (normalized == null) {
            return null;
        }
        normalized = normalized.toUpperCase(Locale.ROOT);
        if (!allowed.contains(normalized)) {
            throw new IllegalArgumentException(field + " contains an unsupported value");
        }
        return normalized;
    }

    private static String normalizeOptional(
            String value,
            int maximumLength,
            String field,
            boolean lowercase
    ) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.length() > maximumLength || normalized.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " is invalid or too long");
        }
        return lowercase ? normalized.toLowerCase(Locale.ROOT) : normalized;
    }

    private static final class SetValues {
        private static final java.util.Set<String> ORIGIN_SCOPES = java.util.Set.of(
                "INTERNET",
                "EXTERNAL_PARTNER",
                "INTERNAL_ENTERPRISE",
                "LOCAL_SEGMENT",
                "OTHER",
                "UNKNOWN"
        );
        private static final java.util.Set<String> REACHABILITY_STATUSES = java.util.Set.of(
                "REACHABLE",
                "NOT_REACHABLE",
                "UNKNOWN"
        );

        private SetValues() {
        }
    }
}
