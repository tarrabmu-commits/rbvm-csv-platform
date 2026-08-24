package io.rbvm.postgres;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** PostgreSQL append/replay store for canonicalized MVP treatment-priority results. */
public final class PostgresCanonicalMvpPriorityStore implements CanonicalMvpPriorityStore {
    private static final String TENANT_KEY = "local";
    private final JdbcConnectionFactory connections;

    public PostgresCanonicalMvpPriorityStore(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
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
        Objects.requireNonNull(importId, "importId");
        Objects.requireNonNull(csvRunId, "csvRunId");
        Objects.requireNonNull(analysisId, "analysisId");
        Objects.requireNonNull(sourceCsvSha256, "sourceCsvSha256");
        Objects.requireNonNull(priorityCsvSha256, "priorityCsvSha256");
        Objects.requireNonNull(rows, "rows");
        Objects.requireNonNull(materializedAt, "materializedAt");
        if (rows.isEmpty()) throw new ConflictException("Priority artifact contains no finding rows");

        Map<Long, PriorityRow> bySourceRow = new HashMap<>();
        for (PriorityRow row : rows) {
            if (!METHOD_SHA256.equals(row.methodSha256())) {
                throw new ConflictException("Priority row method SHA does not match frozen MVP policy V1");
            }
            PriorityRow prior = bySourceRow.put(row.sourceRowNumber(), row);
            if (prior != null) throw new ConflictException("Duplicate source row in priority artifact");
        }

        try (Connection connection = connections.open()) {
            connection.setAutoCommit(false);
            try {
                ImportIdentity identity = importIdentity(connection, importId);
                if (identity == null) {
                    throw new NotFoundException("Completed canonical import does not exist");
                }
                if (!identity.fileSha256().equals(sourceCsvSha256)) {
                    throw new ConflictException(
                            "CSV-first source SHA does not match canonical import file SHA; inferred association is forbidden");
                }

                Map<Long, UUID> lineage = exactLineage(connection, identity.tenantId(), importId);
                if (lineage.isEmpty()) {
                    throw new ConflictException("Canonical import has no exact source-row to Finding lineage");
                }

                Map<UUID, FindingCandidate> candidates = new LinkedHashMap<>();
                for (Map.Entry<Long, UUID> link : lineage.entrySet()) {
                    long sourceRow = link.getKey();
                    PriorityRow priority = bySourceRow.get(sourceRow);
                    if (priority == null) {
                        throw new ConflictException(
                                "Priority artifact is missing canonical source row " + sourceRow);
                    }
                    UUID findingId = link.getValue();
                    FindingCandidate existing = candidates.get(findingId);
                    if (existing == null) {
                        candidates.put(findingId, new FindingCandidate(priority, new ArrayList<>(List.of(sourceRow))));
                    } else {
                        if (!samePriority(existing.priority(), priority)) {
                            throw new ConflictException(
                                    "Multiple exact source rows map to one Finding with different MVP-priority outputs");
                        }
                        existing.sourceRows().add(sourceRow);
                    }
                }

                int inserted = 0;
                int replayed = 0;
                List<Map.Entry<UUID, FindingCandidate>> ordered = new ArrayList<>(candidates.entrySet());
                ordered.sort(Map.Entry.comparingByKey());
                for (Map.Entry<UUID, FindingCandidate> item : ordered) {
                    item.getValue().sourceRows().sort(Comparator.naturalOrder());
                    String resultSha = resultSha256(
                            item.getKey(), importId, csvRunId, analysisId,
                            sourceCsvSha256, priorityCsvSha256, item.getValue());
                    if (insert(connection, identity.tenantId(), item.getKey(), importId, csvRunId,
                            analysisId, sourceCsvSha256, priorityCsvSha256, resultSha,
                            item.getValue(), materializedAt)) {
                        inserted++;
                    } else {
                        String existing = existingResultSha(connection, identity.tenantId(), item.getKey(),
                                importId, csvRunId, analysisId);
                        if (!resultSha.equals(existing)) {
                            throw new ConflictException(
                                    "Canonical Finding priority identity already exists with different immutable content");
                        }
                        replayed++;
                    }
                }
                connection.commit();
                return new MaterializationResult(
                        candidates.size(), inserted, replayed, lineage.size(),
                        sourceCsvSha256, priorityCsvSha256);
            } catch (IOException | SQLException | RuntimeException exception) {
                connection.rollback();
                if (exception instanceof IOException io) throw io;
                if (exception instanceof SQLException sql) {
                    throw PostgresErrors.sanitized("Could not materialize canonical MVP priority", sql);
                }
                throw exception;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("Could not materialize canonical MVP priority", exception);
        }
    }

    private static ImportIdentity importIdentity(Connection connection, UUID importId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT ir.tenant_id, ir.file_sha256
                FROM rbvm.import_run ir
                JOIN rbvm.tenant t ON t.id = ir.tenant_id
                WHERE ir.id = ? AND t.tenant_key = ? AND ir.status = 'COMPLETED'
                """)) {
            statement.setObject(1, importId);
            statement.setString(2, TENANT_KEY);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) return null;
                return new ImportIdentity(
                        result.getObject("tenant_id", UUID.class),
                        result.getString("file_sha256").trim());
            }
        }
    }

    private static Map<Long, UUID> exactLineage(Connection connection, UUID tenantId, UUID importId)
            throws SQLException, ConflictException {
        Map<Long, UUID> output = new LinkedHashMap<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT io.source_row_number, e.id AS finding_id
                FROM rbvm.import_observation io
                JOIN rbvm.observation o
                  ON o.tenant_id = io.tenant_id AND o.id = io.observation_id
                JOIN rbvm.exposure_observation eo
                  ON eo.tenant_id = o.tenant_id AND eo.observation_id = o.id
                JOIN rbvm.exposure e
                  ON e.tenant_id = eo.tenant_id AND e.id = eo.exposure_id
                WHERE io.tenant_id = ? AND io.import_id = ?
                ORDER BY io.source_row_number, e.id
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, importId);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    long sourceRow = result.getLong("source_row_number");
                    UUID findingId = result.getObject("finding_id", UUID.class);
                    UUID prior = output.putIfAbsent(sourceRow, findingId);
                    if (prior != null && !prior.equals(findingId)) {
                        throw new ConflictException(
                                "One canonical source row resolves to multiple Findings; materialization is ambiguous");
                    }
                }
            }
        }
        return output;
    }

    private static boolean insert(
            Connection connection,
            UUID tenantId,
            UUID findingId,
            UUID importId,
            UUID csvRunId,
            UUID analysisId,
            String sourceCsvSha256,
            String priorityCsvSha256,
            String resultSha256,
            FindingCandidate candidate,
            Instant materializedAt
    ) throws SQLException {
        PriorityRow row = candidate.priority();
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.finding_mvp_priority_result(
                    id, tenant_id, finding_id, import_id, csv_run_id, analysis_id,
                    method_id, method_version, method_sha256,
                    source_csv_sha256, priority_csv_sha256, result_sha256,
                    priority_status, priority_front, dominated_by, dominates,
                    blockers, explanation, kev_listed, internet_facing, asset_criticality,
                    epss_probability, contextual_cvss_v4, source_row_numbers, materialized_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, finding_id, import_id, csv_run_id, analysis_id, method_sha256)
                DO NOTHING
                """)) {
            statement.setObject(1, UUID.randomUUID());
            statement.setObject(2, tenantId);
            statement.setObject(3, findingId);
            statement.setObject(4, importId);
            statement.setObject(5, csvRunId);
            statement.setObject(6, analysisId);
            statement.setString(7, METHOD_ID);
            statement.setString(8, METHOD_SHA256);
            statement.setString(9, sourceCsvSha256);
            statement.setString(10, priorityCsvSha256);
            statement.setString(11, resultSha256);
            statement.setString(12, row.status());
            nullableInteger(statement, 13, row.front());
            nullableLong(statement, 14, row.dominatedBy());
            nullableLong(statement, 15, row.dominates());
            statement.setString(16, row.blockers());
            statement.setString(17, row.explanation());
            nullableBoolean(statement, 18, row.kevListed());
            statement.setString(19, row.internetFacing());
            statement.setString(20, row.assetCriticality());
            statement.setBigDecimal(21, row.epssProbability());
            statement.setBigDecimal(22, row.contextualCvssV4());
            Long[] sourceRows = candidate.sourceRows().toArray(Long[]::new);
            try (Array array = connection.createArrayOf("int8", sourceRows)) {
                statement.setArray(23, array);
                statement.setTimestamp(24, Timestamp.from(materializedAt));
                return statement.executeUpdate() == 1;
            }
        }
    }

    private static String existingResultSha(
            Connection connection,
            UUID tenantId,
            UUID findingId,
            UUID importId,
            UUID csvRunId,
            UUID analysisId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT result_sha256
                FROM rbvm.finding_mvp_priority_result
                WHERE tenant_id = ? AND finding_id = ? AND import_id = ?
                  AND csv_run_id = ? AND analysis_id = ? AND method_sha256 = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, findingId);
            statement.setObject(3, importId);
            statement.setObject(4, csvRunId);
            statement.setObject(5, analysisId);
            statement.setString(6, METHOD_SHA256);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? result.getString(1).trim() : null;
            }
        }
    }

    private static boolean samePriority(PriorityRow left, PriorityRow right) {
        return Objects.equals(left.status(), right.status())
                && Objects.equals(left.front(), right.front())
                && Objects.equals(left.dominatedBy(), right.dominatedBy())
                && Objects.equals(left.dominates(), right.dominates())
                && Objects.equals(left.blockers(), right.blockers())
                && Objects.equals(left.explanation(), right.explanation())
                && Objects.equals(left.methodSha256(), right.methodSha256())
                && Objects.equals(left.kevListed(), right.kevListed())
                && Objects.equals(left.internetFacing(), right.internetFacing())
                && Objects.equals(left.assetCriticality(), right.assetCriticality())
                && decimalEquals(left.epssProbability(), right.epssProbability())
                && decimalEquals(left.contextualCvssV4(), right.contextualCvssV4());
    }

    private static boolean decimalEquals(BigDecimal left, BigDecimal right) {
        if (left == null || right == null) return left == right;
        return left.compareTo(right) == 0;
    }

    private static String resultSha256(
            UUID findingId,
            UUID importId,
            UUID csvRunId,
            UUID analysisId,
            String sourceCsvSha256,
            String priorityCsvSha256,
            FindingCandidate candidate
    ) {
        StringBuilder canonical = new StringBuilder("RBVM_CANONICAL_MVP_PRIORITY_RESULT_V1");
        append(canonical, findingId.toString());
        append(canonical, importId.toString());
        append(canonical, csvRunId.toString());
        append(canonical, analysisId.toString());
        append(canonical, METHOD_ID);
        append(canonical, METHOD_SHA256);
        append(canonical, sourceCsvSha256);
        append(canonical, priorityCsvSha256);
        PriorityRow row = candidate.priority();
        append(canonical, row.status());
        append(canonical, value(row.front()));
        append(canonical, value(row.dominatedBy()));
        append(canonical, value(row.dominates()));
        append(canonical, row.blockers());
        append(canonical, row.explanation());
        append(canonical, value(row.kevListed()));
        append(canonical, row.internetFacing());
        append(canonical, row.assetCriticality());
        append(canonical, decimal(row.epssProbability()));
        append(canonical, decimal(row.contextualCvssV4()));
        for (Long sourceRow : candidate.sourceRows()) append(canonical, Long.toString(sourceRow));
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of().formatHex(
                    digest.digest(canonical.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required", exception);
        }
    }

    private static void append(StringBuilder target, String value) {
        String normalized = value == null ? "" : value;
        target.append('|').append(normalized.length()).append(':').append(normalized);
    }

    private static String value(Object value) {
        return value == null ? "" : value.toString();
    }

    private static String decimal(BigDecimal value) {
        return value == null ? "" : value.stripTrailingZeros().toPlainString();
    }

    private static void nullableInteger(PreparedStatement statement, int index, Integer value)
            throws SQLException {
        if (value == null) statement.setNull(index, java.sql.Types.INTEGER);
        else statement.setInt(index, value);
    }

    private static void nullableLong(PreparedStatement statement, int index, Long value)
            throws SQLException {
        if (value == null) statement.setNull(index, java.sql.Types.BIGINT);
        else statement.setLong(index, value);
    }

    private static void nullableBoolean(PreparedStatement statement, int index, Boolean value)
            throws SQLException {
        if (value == null) statement.setNull(index, java.sql.Types.BOOLEAN);
        else statement.setBoolean(index, value);
    }

    private record ImportIdentity(UUID tenantId, String fileSha256) {
    }

    private record FindingCandidate(PriorityRow priority, List<Long> sourceRows) {
    }
}
