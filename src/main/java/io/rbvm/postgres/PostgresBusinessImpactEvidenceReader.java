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
import java.util.Set;

/** PostgreSQL current-evidence reader for independent qualitative Business/Mission Impact evidence. */
public final class PostgresBusinessImpactEvidenceReader implements BusinessImpactEvidenceReader {
    private static final String TENANT_KEY = "local";
    private final JdbcConnectionFactory connections;

    public PostgresBusinessImpactEvidenceReader(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    @Override
    public Map<String, Object> currentEvidence(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String businessService,
            String impactSource,
            String impactDimension,
            String impactLevel
    ) throws IOException {
        if (limit < 1 || limit > 500) {
            throw new IllegalArgumentException("limit must be between 1 and 500");
        }
        String normalizedAsset = normalizeOptional(assetPrefix, 160, "asset", true);
        String normalizedProfile = normalizeProfile(sourceProfileKey);
        String normalizedService = normalizeOptional(businessService, 256, "businessService", true);
        String normalizedSource = normalizeOptional(impactSource, 256, "impactSource", false);
        String normalizedDimension = normalizeEnum(
                impactDimension,
                "impactDimension",
                Set.of("AVAILABILITY", "INTEGRITY", "CONFIDENTIALITY", "SAFETY", "FINANCIAL",
                        "REGULATORY", "OPERATIONAL", "REPUTATIONAL", "MISSION", "OTHER", "UNKNOWN")
        );
        String normalizedLevel = normalizeEnum(
                impactLevel,
                "impactLevel",
                Set.of("SEVERE", "HIGH", "MODERATE", "LOW", "NEGLIGIBLE", "UNKNOWN")
        );

        List<Map<String, Object>> items = new ArrayList<>();
        String sql = """
                SELECT
                    e.source_profile_key,
                    e.asset_identity_basis,
                    e.asset_name_observed,
                    e.asset_source_id,
                    e.business_service,
                    e.impact_dimension,
                    e.impact_level,
                    e.impact_method,
                    e.impact_statement,
                    e.impact_source,
                    e.source_sha256,
                    e.observed_at,
                    e.evidence_ingested_at,
                    e.snapshot_ingested_at
                FROM rbvm.current_business_impact_evidence e
                JOIN rbvm.tenant t ON t.id = e.tenant_id
                WHERE t.tenant_key = ?
                  AND (? IS NULL OR lower(e.asset_name_observed) LIKE ?
                       OR lower(COALESCE(e.asset_source_id, '')) LIKE ?)
                  AND (? IS NULL OR e.source_profile_key = ?)
                  AND (? IS NULL OR e.business_service_normalized LIKE ?)
                  AND (? IS NULL OR e.impact_source = ?)
                  AND (? IS NULL OR e.impact_dimension = ?)
                  AND (? IS NULL OR e.impact_level = ?)
                ORDER BY e.observed_at DESC,
                         e.asset_name_observed,
                         e.impact_source,
                         e.business_service_normalized,
                         e.impact_dimension
                LIMIT ?
                """;
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, TENANT_KEY);
            bindPrefix(statement, 2, 3, 4, normalizedAsset);
            statement.setString(5, normalizedProfile);
            statement.setString(6, normalizedProfile);
            if (normalizedService == null) {
                statement.setString(7, null);
                statement.setString(8, null);
            } else {
                statement.setString(7, normalizedService);
                statement.setString(8, normalizedService + "%");
            }
            statement.setString(9, normalizedSource);
            statement.setString(10, normalizedSource);
            statement.setString(11, normalizedDimension);
            statement.setString(12, normalizedDimension);
            statement.setString(13, normalizedLevel);
            statement.setString(14, normalizedLevel);
            statement.setInt(15, limit);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("sourceProfileKey", rows.getString(1));
                    item.put("assetIdentityBasis", rows.getString(2));
                    item.put("assetName", rows.getString(3));
                    item.put("assetSourceId", rows.getString(4));
                    item.put("businessService", rows.getString(5));
                    item.put("impactDimension", rows.getString(6));
                    item.put("impactLevel", rows.getString(7));
                    item.put("impactMethod", rows.getString(8));
                    item.put("impactStatement", rows.getString(9));
                    item.put("impactSource", rows.getString(10));
                    item.put("impactSourceSha256", rows.getString(11).trim());
                    item.put("impactObservedAt", rows.getTimestamp(12).toInstant().toString());
                    item.put("evidenceIngestedAt", rows.getTimestamp(13).toInstant().toString());
                    item.put("snapshotIngestedAt", rows.getTimestamp(14).toInstant().toString());
                    items.add(Collections.unmodifiableMap(new LinkedHashMap<>(item)));
                }
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("Could not read PostgreSQL Business Impact evidence", exception);
        }

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("semantics", "CURRENT_PER_SOURCE_ASSET_SERVICE_BUSINESS_MISSION_IMPACT_EVIDENCE");
        output.put("limit", limit);
        output.put("assetPrefix", normalizedAsset);
        output.put("sourceProfileKey", normalizedProfile);
        output.put("businessService", normalizedService);
        output.put("impactSource", normalizedSource);
        output.put("impactDimension", normalizedDimension);
        output.put("impactLevel", normalizedLevel);
        output.put("count", items.size());
        output.put("items", List.copyOf(items));
        return Collections.unmodifiableMap(output);
    }

    private static void bindPrefix(
            PreparedStatement statement,
            int markerIndex,
            int nameIndex,
            int sourceIdIndex,
            String value
    ) throws SQLException {
        if (value == null) {
            statement.setString(markerIndex, null);
            statement.setString(nameIndex, null);
            statement.setString(sourceIdIndex, null);
        } else {
            statement.setString(markerIndex, value);
            statement.setString(nameIndex, value + "%");
            statement.setString(sourceIdIndex, value + "%");
        }
    }

    private static String normalizeProfile(String value) {
        String normalized = normalizeOptional(value, 128, "sourceProfile", false);
        if (normalized == null) return null;
        if (!normalized.matches("[A-Za-z0-9._:-]+")) {
            throw new IllegalArgumentException("sourceProfile contains unsupported characters");
        }
        return normalized;
    }

    private static String normalizeEnum(String value, String field, Set<String> allowed) {
        String normalized = normalizeOptional(value, 64, field, false);
        if (normalized == null) return null;
        normalized = normalized.toUpperCase(Locale.ROOT);
        if (!allowed.contains(normalized)) {
            throw new IllegalArgumentException(field + " contains an unsupported value");
        }
        return normalized;
    }

    private static String normalizeOptional(String value, int max, String field, boolean lowercase) {
        if (value == null || value.isBlank()) return null;
        String normalized = value.trim();
        if (normalized.length() > max || normalized.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " is invalid or too long");
        }
        return lowercase ? normalized.toLowerCase(Locale.ROOT) : normalized;
    }
}
