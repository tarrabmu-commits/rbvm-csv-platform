package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.postgres.DecisionInputRuntimeAccess.SnapshotHistoryPage;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Read-only paged history of immutable Decision Input snapshot identities for one Finding. */
public final class PostgresDecisionInputHistoryReader
        implements DecisionInputRuntimeAccess.HistoryReader {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 17;

    private final JdbcConnectionFactory connections;
    private final DecisionInputSnapshotStore snapshots;

    public PostgresDecisionInputHistoryReader(
            JdbcConnectionFactory connections,
            DecisionInputSnapshotStore snapshots,
            int schemaVersion
    ) throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
        if (schemaVersion < REQUIRED_SCHEMA_VERSION) {
            throw new IOException(
                    "PostgreSQL schema version " + schemaVersion
                            + " is older than Decision Input history version "
                            + REQUIRED_SCHEMA_VERSION
            );
        }
    }

    @Override
    public SnapshotHistoryPage history(
            UUID findingId,
            int limit,
            Instant beforeEvaluatedAt,
            String beforeSnapshotSha256
    ) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        requireLimit(limit);
        if ((beforeEvaluatedAt == null) != (beforeSnapshotSha256 == null)) {
            throw new IllegalArgumentException(
                    "Decision Input history cursor requires both beforeEvaluatedAt and beforeSnapshotSha256"
            );
        }
        if (beforeSnapshotSha256 != null) {
            requireSha(beforeSnapshotSha256, "beforeSnapshotSha256");
        }

        List<Identity> identities = new ArrayList<>();
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            String sql = beforeEvaluatedAt == null ? """
                    SELECT snapshot_sha256, evaluated_at
                    FROM rbvm.decision_input_snapshot
                    WHERE tenant_id = ? AND finding_id = ?
                    ORDER BY evaluated_at DESC, snapshot_sha256 DESC
                    LIMIT ?
                    """ : """
                    SELECT snapshot_sha256, evaluated_at
                    FROM rbvm.decision_input_snapshot
                    WHERE tenant_id = ?
                      AND finding_id = ?
                      AND (
                            evaluated_at < ?
                            OR (evaluated_at = ? AND snapshot_sha256 < ?)
                      )
                    ORDER BY evaluated_at DESC, snapshot_sha256 DESC
                    LIMIT ?
                    """;
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setObject(1, tenantId);
                statement.setObject(2, findingId);
                int parameter = 3;
                if (beforeEvaluatedAt != null) {
                    Timestamp cursorTime = Timestamp.from(beforeEvaluatedAt);
                    statement.setTimestamp(parameter++, cursorTime);
                    statement.setTimestamp(parameter++, cursorTime);
                    statement.setString(parameter++, beforeSnapshotSha256);
                }
                statement.setInt(parameter, limit + 1);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        identities.add(new Identity(
                                rows.getString(1).trim(),
                                rows.getTimestamp(2).toInstant()
                        ));
                    }
                }
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL Decision Input snapshot history",
                    exception
            );
        }

        boolean hasMore = identities.size() > limit;
        if (hasMore) {
            identities.remove(identities.size() - 1);
        }
        List<RbvmDecisionInputSnapshot> page = new ArrayList<>(identities.size());
        for (Identity identity : identities) {
            RbvmDecisionInputSnapshot snapshot = snapshots
                    .findBySha256(identity.snapshotSha256())
                    .orElseThrow(() -> new IOException(
                            "Decision Input history references a missing snapshot identity"
                    ));
            if (!findingId.equals(snapshot.findingId())) {
                throw new IOException(
                        "Decision Input history snapshot does not match requested Finding identity"
                );
            }
            page.add(snapshot);
        }

        if (!hasMore || identities.isEmpty()) {
            return new SnapshotHistoryPage(page, null, null);
        }
        Identity last = identities.get(identities.size() - 1);
        return new SnapshotHistoryPage(
                page,
                last.evaluatedAt(),
                last.snapshotSha256()
        );
    }

    private static UUID requireTenant(Connection connection) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT id FROM rbvm.tenant WHERE tenant_key = ?")) {
            statement.setString(1, TENANT_KEY);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new IOException(
                            "PostgreSQL projection tenant has not been initialized before Decision Input history access"
                    );
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static void requireLimit(int limit) {
        if (limit < 1 || limit > 500) {
            throw new IllegalArgumentException("limit must be between 1 and 500");
        }
    }

    private static void requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }

    private record Identity(String snapshotSha256, Instant evaluatedAt) {
        private Identity {
            requireSha(snapshotSha256, "snapshotSha256");
            Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        }
    }
}
