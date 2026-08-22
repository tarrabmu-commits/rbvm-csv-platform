package io.rbvm.postgres;

import io.rbvm.context.FindingBusinessServiceLink;
import io.rbvm.context.FindingBusinessServiceLink.ChangeDraft;
import io.rbvm.context.FindingBusinessServiceLink.LinkMethod;
import io.rbvm.context.FindingBusinessServiceLink.LinkStatus;
import io.rbvm.context.FindingBusinessServiceLinkRegistry;
import io.rbvm.context.FindingBusinessServiceLinkRegistry.CurrentLookup;
import io.rbvm.context.FindingBusinessServiceLinkRegistry.CurrentPage;
import io.rbvm.context.FindingBusinessServiceLinkRegistry.HistoryPage;
import io.rbvm.context.FindingBusinessServiceLinkRegistry.MutationResult;
import io.rbvm.context.FindingBusinessServiceLinkRegistry.MutationStatus;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.Normalizer;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** PostgreSQL registry for customer-confirmed Finding-to-business-service link streams. */
public final class PostgresFindingBusinessServiceLinkRegistry
        implements FindingBusinessServiceLinkRegistry {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 21;
    private static final int MAX_PAGE_SIZE = 500;
    private static final long WRITE_LOCK = 5_441_927_014_630_881_212L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresFindingBusinessServiceLinkRegistry(
            JdbcConnectionFactory connections,
            boolean migrate
    ) throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresFindingBusinessServiceLinkRegistry(
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

    PostgresFindingBusinessServiceLinkRegistry(
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
    public MutationResult revise(UUID findingId, int expectedRevision, ChangeDraft nextState)
            throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        Objects.requireNonNull(nextState, "nextState");
        if (expectedRevision < 0) {
            throw new IllegalArgumentException("expectedRevision must be zero or positive");
        }
        String service = normalizeService(nextState.businessService());

        try (Connection connection = connections.open()) {
            beginWriteTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                if (!findingExists(connection, tenantId, findingId)) {
                    connection.commit();
                    return new MutationResult(MutationStatus.FINDING_NOT_FOUND, null);
                }

                FindingBusinessServiceLink current = loadCurrent(
                        connection, tenantId, findingId, service);
                if (current == null) {
                    if (expectedRevision != 0) {
                        connection.commit();
                        return new MutationResult(MutationStatus.REVISION_CONFLICT, null);
                    }
                    FindingBusinessServiceLink created = materialize(findingId, 1, nextState);
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

                FindingBusinessServiceLink updated = materialize(
                        findingId, currentRevision + 1, nextState);
                insertEvent(connection, tenantId, updated);
                connection.commit();
                return new MutationResult(MutationStatus.UPDATED, updated);
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) {
                    throw ioException;
                }
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL Finding business-service revision failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL Finding business-service transaction",
                    exception
            );
        }
    }

    @Override
    public CurrentLookup current(UUID findingId, String businessService) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        String service = normalizeService(businessService);
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            if (!findingExists(connection, tenantId, findingId)) {
                return new CurrentLookup(false, null);
            }
            return new CurrentLookup(
                    true,
                    loadCurrent(connection, tenantId, findingId, service)
            );
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL Finding business-service state",
                    exception
            );
        }
    }

    @Override
    public Optional<HistoryPage> history(
            UUID findingId,
            String businessService,
            int limit,
            Integer beforeRevision
    ) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        requirePage(limit, beforeRevision);
        String service = normalizeService(businessService);
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            if (!findingExists(connection, tenantId, findingId)) {
                return Optional.empty();
            }
            List<FindingBusinessServiceLink> events = new ArrayList<>();
            String sql = """
                    SELECT id, finding_id, revision, link_status,
                           business_service_normalized, link_method, evidence_sha256,
                           changed_by, change_note, recorded_at
                    FROM rbvm.finding_business_service_link_event
                    WHERE tenant_id = ? AND finding_id = ?
                      AND business_service_normalized = ?
                    """ + (beforeRevision == null ? "" : " AND revision < ?")
                    + " ORDER BY revision DESC LIMIT ?";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                int index = 1;
                statement.setObject(index++, tenantId);
                statement.setObject(index++, findingId);
                statement.setString(index++, service);
                if (beforeRevision != null) {
                    statement.setInt(index++, beforeRevision);
                }
                statement.setInt(index, limit + 1);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        events.add(map(rows));
                    }
                }
            }
            Integer next = null;
            if (events.size() > limit) {
                events = new ArrayList<>(events.subList(0, limit));
                next = events.get(events.size() - 1).revision();
            }
            return Optional.of(new HistoryPage(findingId, service, events, next));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL Finding business-service history",
                    exception
            );
        }
    }

    @Override
    public Optional<CurrentPage> listCurrent(UUID findingId, int limit, UUID afterEventId)
            throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        requireListPage(limit);
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            if (!findingExists(connection, tenantId, findingId)) {
                return Optional.empty();
            }
            List<FindingBusinessServiceLink> links = new ArrayList<>();
            String sql = """
                    SELECT link_event_id, finding_id, revision, link_status,
                           business_service_normalized, link_method, evidence_sha256,
                           changed_by, change_note, recorded_at
                    FROM rbvm.current_finding_business_service_link
                    WHERE tenant_id = ? AND finding_id = ?
                    """ + (afterEventId == null ? "" : " AND link_event_id > ?")
                    + " ORDER BY link_event_id ASC LIMIT ?";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                int index = 1;
                statement.setObject(index++, tenantId);
                statement.setObject(index++, findingId);
                if (afterEventId != null) {
                    statement.setObject(index++, afterEventId);
                }
                statement.setInt(index, limit + 1);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        links.add(map(rows));
                    }
                }
            }
            UUID next = null;
            if (links.size() > limit) {
                links = new ArrayList<>(links.subList(0, limit));
                next = links.get(links.size() - 1).eventId();
            }
            return Optional.of(new CurrentPage(findingId, links, next));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not list PostgreSQL Finding business-service states",
                    exception
            );
        }
    }

    public int schemaVersion() {
        return schemaVersion;
    }

    private FindingBusinessServiceLink materialize(
            UUID findingId,
            int revision,
            ChangeDraft draft
    ) {
        String sha = FindingBusinessServiceLink.evidenceSha256(
                findingId,
                revision,
                draft.linkStatus(),
                draft.businessService()
        );
        return new FindingBusinessServiceLink(
                UUID.randomUUID(),
                findingId,
                revision,
                draft.linkStatus(),
                draft.businessService(),
                LinkMethod.CUSTOMER_CONFIRMED,
                sha,
                draft.changedBy(),
                draft.changeNote(),
                clock.instant()
        );
    }

    private static void insertEvent(
            Connection connection,
            UUID tenantId,
            FindingBusinessServiceLink event
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.finding_business_service_link_event(
                    id, tenant_id, finding_id, revision, link_status,
                    business_service_normalized, link_method, evidence_sha256,
                    changed_by, change_note, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, event.eventId());
            statement.setObject(2, tenantId);
            statement.setObject(3, event.findingId());
            statement.setInt(4, event.revision());
            statement.setString(5, event.linkStatus().name());
            statement.setString(6, event.businessService());
            statement.setString(7, event.linkMethod().name());
            statement.setString(8, event.evidenceSha256());
            statement.setString(9, event.changedBy());
            statement.setString(10, event.changeNote());
            statement.setTimestamp(11, Timestamp.from(event.recordedAt()));
            statement.executeUpdate();
        }
    }

    private static FindingBusinessServiceLink loadCurrent(
            Connection connection,
            UUID tenantId,
            UUID findingId,
            String businessService
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT link_event_id, finding_id, revision, link_status,
                       business_service_normalized, link_method, evidence_sha256,
                       changed_by, change_note, recorded_at
                FROM rbvm.current_finding_business_service_link
                WHERE tenant_id = ? AND finding_id = ?
                  AND business_service_normalized = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, findingId);
            statement.setString(3, businessService);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? map(rows) : null;
            }
        }
    }

    private static FindingBusinessServiceLink map(ResultSet rows) throws SQLException {
        return new FindingBusinessServiceLink(
                rows.getObject(1, UUID.class),
                rows.getObject(2, UUID.class),
                rows.getInt(3),
                LinkStatus.valueOf(rows.getString(4)),
                rows.getString(5),
                LinkMethod.valueOf(rows.getString(6)),
                rows.getString(7).trim(),
                rows.getString(8),
                rows.getString(9),
                rows.getTimestamp(10).toInstant()
        );
    }

    private static boolean findingExists(
            Connection connection,
            UUID tenantId,
            UUID findingId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT 1 FROM rbvm.exposure WHERE tenant_id = ? AND id = ?")) {
            statement.setObject(1, tenantId);
            statement.setObject(2, findingId);
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
                if (!rows.next()) {
                    throw new IOException("RBVM tenant is not initialized");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static void beginWriteTransaction(Connection connection) throws SQLException {
        connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
        connection.setAutoCommit(false);
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pg_advisory_xact_lock(?)")) {
            statement.setLong(1, WRITE_LOCK);
            statement.execute();
        }
    }

    private static void rollback(Connection connection, Throwable original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private static void requirePage(int limit, Integer beforeRevision) {
        requireListPage(limit);
        if (beforeRevision != null && beforeRevision < 1) {
            throw new IllegalArgumentException("beforeRevision must be positive");
        }
    }

    private static void requireListPage(int limit) {
        if (limit < 1 || limit > MAX_PAGE_SIZE) {
            throw new IllegalArgumentException("limit must be between 1 and " + MAX_PAGE_SIZE);
        }
    }

    private static void requireSchemaVersion(int version) throws IOException {
        if (version < REQUIRED_SCHEMA_VERSION) {
            throw new IOException(
                    "PostgreSQL schema version " + version
                            + " is older than required version " + REQUIRED_SCHEMA_VERSION);
        }
    }

    private static String normalizeService(String value) {
        Objects.requireNonNull(value, "businessService");
        String trimmed = value.trim();
        if (trimmed.isEmpty() || trimmed.length() > 256 || trimmed.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException("businessService is blank, invalid, or too long");
        }
        return Normalizer.normalize(trimmed, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }
}
