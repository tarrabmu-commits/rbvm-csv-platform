package io.rbvm.postgres;

import io.rbvm.asset.ManagedAsset;
import io.rbvm.asset.ManagedAsset.ClassificationMethod;
import io.rbvm.asset.ManagedAsset.LifecycleStatus;
import io.rbvm.asset.ManagedAsset.Revision;
import io.rbvm.asset.ManagedAssetRegistry.LifecycleFilter;
import io.rbvm.asset.ManagedAssetRegistry.ManagedAssetPage;
import io.rbvm.asset.ManagedAssetRegistry.RevisionPage;
import io.rbvm.csv.AssetContextCsvEvidence.BusinessCriticality;
import io.rbvm.csv.AssetContextCsvEvidence.Environment;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Tenant-scoped deterministic read surface for current managed assets and immutable history. */
final class PostgresManagedAssetReadStore {
    private static final String TENANT_KEY = "local";
    private static final int MAXIMUM_PAGE_LIMIT = 500;

    private final JdbcConnectionFactory connections;

    PostgresManagedAssetReadStore(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    ManagedAssetPage list(int limit, UUID afterId, LifecycleFilter lifecycleFilter)
            throws IOException {
        requireLimit(limit);
        Objects.requireNonNull(lifecycleFilter, "lifecycleFilter");
        try (Connection connection = connections.open()) {
            beginRead(connection);
            try {
                UUID tenantId = requireTenant(connection);
                List<ManagedAsset> assets = loadCurrentPage(
                        connection,
                        tenantId,
                        limit + 1,
                        afterId,
                        lifecycleFilter
                );
                connection.commit();
                boolean hasMore = assets.size() > limit;
                if (hasMore) {
                    assets = new ArrayList<>(assets.subList(0, limit));
                }
                UUID nextAfterId = hasMore && !assets.isEmpty()
                        ? assets.get(assets.size() - 1).id()
                        : null;
                return new ManagedAssetPage(assets, nextAfterId);
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL managed asset list failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL managed asset read transaction",
                    exception
            );
        }
    }

    Optional<RevisionPage> history(
            UUID managedAssetId,
            int limit,
            Integer beforeRevision
    ) throws IOException {
        Objects.requireNonNull(managedAssetId, "managedAssetId");
        requireLimit(limit);
        if (beforeRevision != null && beforeRevision < 1) {
            throw new IllegalArgumentException("beforeRevision must be positive");
        }
        try (Connection connection = connections.open()) {
            beginRead(connection);
            try {
                UUID tenantId = requireTenant(connection);
                if (!assetExists(connection, tenantId, managedAssetId)) {
                    connection.commit();
                    return Optional.empty();
                }
                List<Revision> revisions = loadHistoryPage(
                        connection,
                        tenantId,
                        managedAssetId,
                        limit + 1,
                        beforeRevision
                );
                connection.commit();
                boolean hasMore = revisions.size() > limit;
                if (hasMore) {
                    revisions = new ArrayList<>(revisions.subList(0, limit));
                }
                Integer nextBeforeRevision = hasMore && !revisions.isEmpty()
                        ? revisions.get(revisions.size() - 1).revision()
                        : null;
                return Optional.of(new RevisionPage(
                        managedAssetId,
                        revisions,
                        nextBeforeRevision
                ));
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL managed asset history read failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL managed asset history transaction",
                    exception
            );
        }
    }

    private static List<ManagedAsset> loadCurrentPage(
            Connection connection,
            UUID tenantId,
            int fetchLimit,
            UUID afterId,
            LifecycleFilter lifecycleFilter
    ) throws SQLException, IOException {
        StringBuilder sql = new StringBuilder("""
                SELECT managed_asset_id, customer_asset_key, created_at,
                       revision_id, revision, lifecycle_status, display_name, environment,
                       business_service, business_owner, business_criticality,
                       classification_method, guide_contract_id, guide_revision,
                       context_source, evidence_sha256, changed_by, change_note, recorded_at
                FROM rbvm.current_managed_asset
                WHERE tenant_id = ?
                """);
        if (afterId != null) {
            sql.append(" AND managed_asset_id > ?\n");
        }
        if (lifecycleFilter != LifecycleFilter.ALL) {
            sql.append(" AND lifecycle_status = ?\n");
        }
        sql.append(" ORDER BY managed_asset_id ASC\n LIMIT ?");

        try (PreparedStatement statement = connection.prepareStatement(sql.toString())) {
            int parameter = 1;
            statement.setObject(parameter++, tenantId);
            if (afterId != null) {
                statement.setObject(parameter++, afterId);
            }
            if (lifecycleFilter != LifecycleFilter.ALL) {
                statement.setString(parameter++, lifecycleFilter.name());
            }
            statement.setInt(parameter, fetchLimit);
            try (ResultSet rows = statement.executeQuery()) {
                List<ManagedAsset> output = new ArrayList<>();
                while (rows.next()) {
                    output.add(mapCurrent(rows));
                }
                return output;
            }
        }
    }

    private static List<Revision> loadHistoryPage(
            Connection connection,
            UUID tenantId,
            UUID managedAssetId,
            int fetchLimit,
            Integer beforeRevision
    ) throws SQLException, IOException {
        StringBuilder sql = new StringBuilder("""
                SELECT id, managed_asset_id, revision, lifecycle_status, display_name, environment,
                       business_service, business_owner, business_criticality,
                       classification_method, guide_contract_id, guide_revision,
                       context_source, evidence_sha256, changed_by, change_note, recorded_at
                FROM rbvm.managed_asset_revision
                WHERE tenant_id = ? AND managed_asset_id = ?
                """);
        if (beforeRevision != null) {
            sql.append(" AND revision < ?\n");
        }
        sql.append(" ORDER BY revision DESC\n LIMIT ?");

        try (PreparedStatement statement = connection.prepareStatement(sql.toString())) {
            int parameter = 1;
            statement.setObject(parameter++, tenantId);
            statement.setObject(parameter++, managedAssetId);
            if (beforeRevision != null) {
                statement.setInt(parameter++, beforeRevision);
            }
            statement.setInt(parameter, fetchLimit);
            try (ResultSet rows = statement.executeQuery()) {
                List<Revision> output = new ArrayList<>();
                while (rows.next()) {
                    output.add(mapRevision(rows));
                }
                return output;
            }
        }
    }

    private static boolean assetExists(
            Connection connection,
            UUID tenantId,
            UUID managedAssetId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT 1
                FROM rbvm.managed_asset
                WHERE tenant_id = ? AND id = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, managedAssetId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next();
            }
        }
    }

    private static ManagedAsset mapCurrent(ResultSet rows) throws SQLException, IOException {
        try {
            UUID managedAssetId = rows.getObject(1, UUID.class);
            Revision revision = new Revision(
                    rows.getObject(4, UUID.class),
                    managedAssetId,
                    rows.getInt(5),
                    LifecycleStatus.valueOf(rows.getString(6)),
                    rows.getString(7),
                    Environment.valueOf(rows.getString(8)),
                    rows.getString(9),
                    rows.getString(10),
                    BusinessCriticality.valueOf(rows.getString(11)),
                    ClassificationMethod.valueOf(rows.getString(12)),
                    rows.getString(13),
                    nullableInteger(rows, 14),
                    rows.getString(15),
                    rows.getString(16).trim(),
                    rows.getString(17),
                    rows.getString(18),
                    rows.getTimestamp(19).toInstant()
            );
            return new ManagedAsset(
                    managedAssetId,
                    rows.getString(2),
                    rows.getTimestamp(3).toInstant(),
                    revision
            );
        } catch (IllegalArgumentException exception) {
            throw new IOException("Persisted managed asset revision is invalid", exception);
        }
    }

    private static Revision mapRevision(ResultSet rows) throws SQLException, IOException {
        try {
            return new Revision(
                    rows.getObject(1, UUID.class),
                    rows.getObject(2, UUID.class),
                    rows.getInt(3),
                    LifecycleStatus.valueOf(rows.getString(4)),
                    rows.getString(5),
                    Environment.valueOf(rows.getString(6)),
                    rows.getString(7),
                    rows.getString(8),
                    BusinessCriticality.valueOf(rows.getString(9)),
                    ClassificationMethod.valueOf(rows.getString(10)),
                    rows.getString(11),
                    nullableInteger(rows, 12),
                    rows.getString(13),
                    rows.getString(14).trim(),
                    rows.getString(15),
                    rows.getString(16),
                    rows.getTimestamp(17).toInstant()
            );
        } catch (IllegalArgumentException exception) {
            throw new IOException("Persisted managed asset revision is invalid", exception);
        }
    }

    private static Integer nullableInteger(ResultSet rows, int column) throws SQLException {
        Object value = rows.getObject(column);
        return value == null ? null : rows.getInt(column);
    }

    private static void beginRead(Connection connection) throws SQLException {
        connection.setReadOnly(true);
        connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
        connection.setAutoCommit(false);
    }

    private static UUID requireTenant(Connection connection) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT id FROM rbvm.tenant WHERE tenant_key = ?")) {
            statement.setString(1, TENANT_KEY);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new IOException(
                            "PostgreSQL projection tenant has not been initialized before managed asset access");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static void requireLimit(int limit) {
        if (limit < 1 || limit > MAXIMUM_PAGE_LIMIT) {
            throw new IllegalArgumentException(
                    "managed asset page limit must be between 1 and " + MAXIMUM_PAGE_LIMIT
            );
        }
    }

    private static void rollback(Connection connection, Throwable cause) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            cause.addSuppressed(rollbackFailure);
        }
    }
}
