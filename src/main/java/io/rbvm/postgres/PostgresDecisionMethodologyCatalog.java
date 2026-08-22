package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionMethodologyPolicy;
import io.rbvm.postgres.DecisionInputRuntimeAccess.MethodologyPage;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Read-only catalog of installed methodology identities; listing order carries no precedence. */
public final class PostgresDecisionMethodologyCatalog
        implements DecisionInputRuntimeAccess.MethodologyCatalog {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 16;

    private final JdbcConnectionFactory connections;
    private final DecisionMethodologyPolicyStore methodologies;

    public PostgresDecisionMethodologyCatalog(
            JdbcConnectionFactory connections,
            DecisionMethodologyPolicyStore methodologies,
            int schemaVersion
    ) throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        this.methodologies = Objects.requireNonNull(methodologies, "methodologies");
        if (schemaVersion < REQUIRED_SCHEMA_VERSION) {
            throw new IOException(
                    "PostgreSQL schema version " + schemaVersion
                            + " is older than Decision Methodology catalog version "
                            + REQUIRED_SCHEMA_VERSION
            );
        }
    }

    @Override
    public MethodologyPage list(int limit, Integer afterRevision) throws IOException {
        requireLimit(limit);
        if (afterRevision != null && afterRevision < 1) {
            throw new IllegalArgumentException("afterRevision must be positive");
        }

        List<Integer> revisions = new ArrayList<>();
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            String sql = afterRevision == null ? """
                    SELECT revision
                    FROM rbvm.decision_methodology_policy
                    WHERE tenant_id = ? AND contract_id = ?
                    ORDER BY revision ASC
                    LIMIT ?
                    """ : """
                    SELECT revision
                    FROM rbvm.decision_methodology_policy
                    WHERE tenant_id = ? AND contract_id = ? AND revision > ?
                    ORDER BY revision ASC
                    LIMIT ?
                    """;
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setObject(1, tenantId);
                statement.setString(2, RbvmDecisionMethodologyPolicy.ID);
                int parameter = 3;
                if (afterRevision != null) {
                    statement.setInt(parameter++, afterRevision);
                }
                statement.setInt(parameter, limit + 1);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        revisions.add(rows.getInt(1));
                    }
                }
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL Decision Methodology catalog",
                    exception
            );
        }

        boolean hasMore = revisions.size() > limit;
        if (hasMore) {
            revisions.remove(revisions.size() - 1);
        }
        List<RbvmDecisionMethodologyPolicy> page = new ArrayList<>(revisions.size());
        for (int revision : revisions) {
            page.add(methodologies.findByRevision(revision).orElseThrow(() -> new IOException(
                    "Decision Methodology catalog references a missing revision"
            )));
        }
        Integer next = hasMore && !revisions.isEmpty()
                ? revisions.get(revisions.size() - 1)
                : null;
        return new MethodologyPage(page, next);
    }

    private static UUID requireTenant(Connection connection) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT id FROM rbvm.tenant WHERE tenant_key = ?")) {
            statement.setString(1, TENANT_KEY);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new IOException(
                            "PostgreSQL projection tenant has not been initialized before Decision Methodology catalog access"
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
}
