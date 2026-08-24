package io.rbvm.postgres;

import java.io.IOException;
import java.math.BigDecimal;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Composite write/read access for V29 canonical MVP-priority results. */
public final class PostgresCanonicalMvpPriorityAccess implements CanonicalMvpPriorityStore {
    private static final String TENANT_KEY = "local";
    private final JdbcConnectionFactory connections;
    private final PostgresCanonicalMvpPriorityStore writer;

    public PostgresCanonicalMvpPriorityAccess(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
        this.writer = new PostgresCanonicalMvpPriorityStore(connections);
    }

    @Override
    public MaterializationResult materialize(
            UUID importId,
            UUID csvRunId,
            UUID analysisId,
            String sourceCsvSha256,
            String priorityCsvSha256,
            List<PriorityRow> rows,
            Instant materializedAt
    ) throws IOException {
        return writer.materialize(
                importId, csvRunId, analysisId, sourceCsvSha256, priorityCsvSha256, rows, materializedAt);
    }

    @Override
    public Optional<PriorityView> latestForFinding(String findingId) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        String normalized = findingId.trim();
        if (normalized.isEmpty()) return Optional.empty();
        UUID internalId = null;
        try {
            internalId = UUID.fromString(normalized);
        } catch (IllegalArgumentException ignored) {
            // Public Finding IDs are SHA-shaped strings; exact comparison is handled below.
        }
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT e.public_id AS finding_public_id,
                            p.import_id, p.csv_run_id, p.analysis_id,
                            p.priority_status, p.priority_front, p.dominated_by, p.dominates,
                            p.blockers, p.explanation, p.kev_listed, p.internet_facing,
                            p.asset_criticality, p.epss_probability, p.contextual_cvss_v4,
                            p.source_row_numbers, p.source_csv_sha256, p.priority_csv_sha256,
                            p.result_sha256, p.materialized_at
                     FROM rbvm.exposure e
                     JOIN rbvm.tenant t ON t.id = e.tenant_id
                     JOIN LATERAL (
                         SELECT result.*
                         FROM rbvm.finding_mvp_priority_result result
                         WHERE result.tenant_id = e.tenant_id AND result.finding_id = e.id
                         ORDER BY result.materialized_at DESC, result.id DESC
                         LIMIT 1
                     ) p ON true
                     WHERE t.tenant_key = ?
                       AND (e.public_id = ? OR (?::uuid IS NOT NULL AND e.id = ?::uuid))
                     LIMIT 1
                     """)) {
            statement.setString(1, TENANT_KEY);
            statement.setString(2, normalized);
            if (internalId == null) {
                statement.setNull(3, java.sql.Types.VARCHAR);
                statement.setNull(4, java.sql.Types.VARCHAR);
            } else {
                statement.setString(3, internalId.toString());
                statement.setString(4, internalId.toString());
            }
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) return Optional.empty();
                return Optional.of(new PriorityView(
                        result.getString("finding_public_id").trim(),
                        result.getObject("import_id", UUID.class),
                        result.getObject("csv_run_id", UUID.class),
                        result.getObject("analysis_id", UUID.class),
                        result.getString("priority_status"),
                        nullableInteger(result, "priority_front"),
                        nullableLong(result, "dominated_by"),
                        nullableLong(result, "dominates"),
                        result.getString("blockers"),
                        result.getString("explanation"),
                        nullableBoolean(result, "kev_listed"),
                        result.getString("internet_facing"),
                        result.getString("asset_criticality"),
                        result.getBigDecimal("epss_probability"),
                        result.getBigDecimal("contextual_cvss_v4"),
                        sourceRows(result.getArray("source_row_numbers")),
                        result.getString("source_csv_sha256").trim(),
                        result.getString("priority_csv_sha256").trim(),
                        result.getString("result_sha256").trim(),
                        timestamp(result, "materialized_at")
                ));
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("Could not read canonical MVP priority", exception);
        }
    }

    private static Integer nullableInteger(ResultSet result, String column) throws SQLException {
        int value = result.getInt(column);
        return result.wasNull() ? null : value;
    }

    private static Long nullableLong(ResultSet result, String column) throws SQLException {
        long value = result.getLong(column);
        return result.wasNull() ? null : value;
    }

    private static Boolean nullableBoolean(ResultSet result, String column) throws SQLException {
        boolean value = result.getBoolean(column);
        return result.wasNull() ? null : value;
    }

    private static Instant timestamp(ResultSet result, String column) throws SQLException {
        Timestamp value = result.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }

    private static List<Long> sourceRows(Array array) throws SQLException {
        if (array == null) return List.of();
        try {
            Object raw = array.getArray();
            List<Long> output = new ArrayList<>();
            if (raw instanceof Long[] values) {
                output.addAll(List.of(values));
            } else if (raw instanceof Object[] values) {
                for (Object value : values) output.add(((Number) value).longValue());
            }
            return List.copyOf(output);
        } finally {
            array.free();
        }
    }
}
