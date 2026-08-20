package io.rbvm.postgres;

import io.rbvm.asset.ScannerManagedAssetLink;
import io.rbvm.asset.ScannerManagedAssetLink.ChangeDraft;
import io.rbvm.asset.ScannerManagedAssetLink.LinkMethod;
import io.rbvm.asset.ScannerManagedAssetLink.LinkStatus;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.CurrentLookup;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.HistoryPage;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.MutationResult;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.MutationStatus;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** PostgreSQL implementation of the explicit customer-confirmed scanner asset link stream. */
public final class PostgresScannerManagedAssetLinkRegistry implements ScannerManagedAssetLinkRegistry {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 19;
    private static final int MAX_PAGE_SIZE = 500;
    private static final long LINK_LOCK = 3_791_523_924_170_061_451L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresScannerManagedAssetLinkRegistry(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresScannerManagedAssetLinkRegistry(
            JdbcConnectionFactory connections,
            boolean migrate,
            Clock clock
    ) throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        this.clock = Objects.requireNonNull(clock, "clock");
        PostgresMigrator migrator = new PostgresMigrator(connections);
        schemaVersion = migrate ? migrator.migrate() : migrator.installedVersion();
        requireSchemaVersion(schemaVersion);
    }

    PostgresScannerManagedAssetLinkRegistry(
            JdbcConnectionFactory connections,
            int schemaVersion,
            Clock clock
    ) throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.schemaVersion = schemaVersion;
        requireSchemaVersion(schemaVersion);
    }

    @Override
    public MutationResult revise(UUID scannerAssetId, int expectedRevision, ChangeDraft nextState)
            throws IOException {
        Objects.requireNonNull(scannerAssetId, "scannerAssetId");
        Objects.requireNonNull(nextState, "nextState");
        if (expectedRevision < 0) {
            throw new IllegalArgumentException("expectedRevision must be zero or positive");
        }

        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                if (!scannerAssetExists(connection, tenantId, scannerAssetId)) {
                    connection.commit();
                    return new MutationResult(MutationStatus.SCANNER_ASSET_NOT_FOUND, null);
                }

                ScannerManagedAssetLink current = loadCurrent(connection, tenantId, scannerAssetId);
                if (nextState.linkStatus() == LinkStatus.LINKED
                        && !managedAssetExists(connection, tenantId, nextState.managedAssetId())) {
                    connection.commit();
                    return new MutationResult(MutationStatus.MANAGED_ASSET_NOT_FOUND, current);
                }

                if (current == null) {
                    if (expectedRevision != 0) {
                        connection.commit();
                        return new MutationResult(MutationStatus.REVISION_CONFLICT, null);
                    }
                    ScannerManagedAssetLink created = materialize(scannerAssetId, 1, nextState);
                    insertEvent(connection, tenantId, created);
                    connection.commit();
                    return new MutationResult(MutationStatus.UPDATED, created);
                }

                int currentRevision = current.revision();
                if (currentRevision == expectedRevision + 1 && current.sameCustomerState(nextState)) {
                    connection.commit();
                    return new MutationResult(MutationStatus.REPLAYED, current);
                }
                if (currentRevision != expectedRevision) {
                    connection.commit();
                    return new MutationResult(MutationStatus.REVISION_CONFLICT, current);
                }
                if (current.sameCustomerState(nextState)) {
                    connection.commit();
                    return new MutationResult(MutationStatus.REPLAYED, current);
                }

                ScannerManagedAssetLink updated = materialize(
                        scannerAssetId,
                        currentRevision + 1,
                        nextState
                );
                insertEvent(connection, tenantId, updated);
                connection.commit();
                return new MutationResult(MutationStatus.UPDATED, updated);
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL scanner-managed-asset link revision failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL scanner-managed-asset link transaction",
                    exception
            );
        }
    }

    @Override
    public CurrentLookup current(UUID scannerAssetId) throws IOException {
        Objects.requireNonNull(scannerAssetId, "scannerAssetId");
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            if (!scannerAssetExists(connection, tenantId, scannerAssetId)) {
                return new CurrentLookup(false, null);
            }
            return new CurrentLookup(true, loadCurrent(connection, tenantId, scannerAssetId));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL scanner-managed-asset link",
                    exception
            );
        }
    }

    @Override
    public Optional<HistoryPage> history(
            UUID scannerAssetId,
            int limit,
            Integer beforeRevision
    ) throws IOException {
        Objects.requireNonNull(scannerAssetId, "scannerAssetId");
        requirePage(limit, beforeRevision);
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            if (!scannerAssetExists(connection, tenantId, scannerAssetId)) {
                return Optional.empty();
            }
            List<ScannerManagedAssetLink> events = new ArrayList<>();
            String sql = """
                    SELECT id, scanner_asset_id, revision, link_status, managed_asset_id,
                           link_method, evidence_sha256, changed_by, change_note, recorded_at
                    FROM rbvm.scanner_managed_asset_link_event
                    WHERE tenant_id = ? AND scanner_asset_id = ?
                    """ + (beforeRevision == null ? "" : " AND revision < ?")
                    + " ORDER BY revision DESC LIMIT ?";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                int index = 1;
                statement.setObject(index++, tenantId);
                statement.setObject(index++, scannerAssetId);
                if (beforeRevision != null) statement.setInt(index++, beforeRevision);
                statement.setInt(index, limit + 1);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) events.add(map(rows));
                }
            }
            Integer next = null;
            if (events.size() > limit) {
                events = new ArrayList<>(events.subList(0, limit));
                next = events.get(events.size() - 1).revision();
            }
            return Optional.of(new HistoryPage(scannerAssetId, events, next));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL scanner-managed-asset link history",
                    exception
            );
        }
    }

    public int schemaVersion() {
        return schemaVersion;
    }

    private ScannerManagedAssetLink materialize(
            UUID scannerAssetId,
            int revision,
            ChangeDraft draft
    ) {
        Instant recordedAt = clock.instant();
        String sha = ScannerManagedAssetLink.evidenceSha256(
                scannerAssetId,
                revision,
                draft.linkStatus(),
                draft.managedAssetId()
        );
        return new ScannerManagedAssetLink(
                UUID.randomUUID(),
                scannerAssetId,
                revision,
                draft.linkStatus(),
                draft.managedAssetId(),
                LinkMethod.CUSTOMER_CONFIRMED,
                sha,
                draft.changedBy(),
                draft.changeNote(),
                recordedAt
        );
    }

    private static void insertEvent(
            Connection connection,
            UUID tenantId,
            ScannerManagedAssetLink event
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.scanner_managed_asset_link_event(
                    id, tenant_id, scanner_asset_id, revision, link_status, managed_asset_id,
                    link_method, evidence_sha256, changed_by, change_note, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, event.eventId());
            statement.setObject(2, tenantId);
            statement.setObject(3, event.scannerAssetId());
            statement.setInt(4, event.revision());
            statement.setString(5, event.linkStatus().name());
            statement.setObject(6, event.managedAssetId());
            statement.setString(7, event.linkMethod().name());
            statement.setString(8, event.evidenceSha256());
            statement.setString(9, event.changedBy());
            statement.setString(10, event.changeNote());
            statement.setTimestamp(11, Timestamp.from(event.recordedAt()));
            statement.executeUpdate();
        }
    }

    private static ScannerManagedAssetLink loadCurrent(
            Connection connection,
            UUID tenantId,
            UUID scannerAssetId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT link_event_id, scanner_asset_id, revision, link_status, managed_asset_id,
                       link_method, evidence_sha256, changed_by, change_note, recorded_at
                FROM rbvm.current_scanner_managed_asset_link
                WHERE tenant_id = ? AND scanner_asset_id = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, scannerAssetId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? map(rows) : null;
            }
        }
    }

    private static ScannerManagedAssetLink map(ResultSet rows) throws SQLException {
        return new ScannerManagedAssetLink(
                rows.getObject(1, UUID.class),
                rows.getObject(2, UUID.class),
                rows.getInt(3),
                LinkStatus.valueOf(rows.getString(4)),
                rows.getObject(5, UUID.class),
                LinkMethod.valueOf(rows.getString(6)),
                rows.getString(7).trim(),
                rows.getString(8),
                rows.getString(9),
                rows.getTimestamp(10).toInstant()
        );
    }

    private static boolean scannerAssetExists(
            Connection connection,
            UUID tenantId,
            UUID scannerAssetId
    ) throws SQLException {
        return exists(connection,
                "SELECT 1 FROM rbvm.asset WHERE tenant_id = ? AND id = ?",
                tenantId,
                scannerAssetId);
    }

    private static boolean managedAssetExists(
            Connection connection,
            UUID tenantId,
            UUID managedAssetId
    ) throws SQLException {
        return exists(connection,
                "SELECT 1 FROM rbvm.managed_asset WHERE tenant_id = ? AND id = ?",
                tenantId,
                managedAssetId);
    }

    private static boolean exists(
            Connection connection,
            String sql,
            UUID tenantId,
            UUID id
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, id);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next();
            }
        }
    }

    private static UUID requireTenant(Connection connection) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT id FROM rbvm.tenant WHERE tenant_key = ?")) {
            statement.setString(1, TENANT_KEY);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) throw new IOException("RBVM tenant is not initialized");
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static void beginTransaction(Connection connection) throws SQLException {
        connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
        connection.setAutoCommit(false);
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pg_advisory_xact_lock(?)")) {
            statement.setLong(1, LINK_LOCK);
            statement.execute();
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private static void requirePage(int limit, Integer beforeRevision) {
        if (limit < 1 || limit > MAX_PAGE_SIZE) {
            throw new IllegalArgumentException("limit must be between 1 and " + MAX_PAGE_SIZE);
        }
        if (beforeRevision != null && beforeRevision < 1) {
            throw new IllegalArgumentException("beforeRevision must be positive");
        }
    }

    private static void requireSchemaVersion(int version) throws IOException {
        if (version < REQUIRED_SCHEMA_VERSION) {
            throw new IOException(
                    "PostgreSQL schema version " + version
                            + " is older than required version " + REQUIRED_SCHEMA_VERSION);
        }
    }
}
