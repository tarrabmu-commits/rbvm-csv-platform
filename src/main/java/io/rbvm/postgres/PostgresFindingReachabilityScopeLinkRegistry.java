package io.rbvm.postgres;

import io.rbvm.context.FindingReachabilityScopeLink;
import io.rbvm.context.FindingReachabilityScopeLink.ChangeDraft;
import io.rbvm.context.FindingReachabilityScopeLink.LinkMethod;
import io.rbvm.context.FindingReachabilityScopeLink.LinkStatus;
import io.rbvm.context.FindingReachabilityScopeLink.OriginScope;
import io.rbvm.context.FindingReachabilityScopeLink.TransportProtocol;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry.CurrentLookup;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry.CurrentPage;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry.HistoryPage;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry.MutationResult;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry.MutationStatus;

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

/** PostgreSQL registry for customer-confirmed Finding-to-reachability-scope link streams. */
public final class PostgresFindingReachabilityScopeLinkRegistry
        implements FindingReachabilityScopeLinkRegistry {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 21;
    private static final int MAX_PAGE_SIZE = 500;
    private static final long WRITE_LOCK = 5_441_927_014_630_881_211L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresFindingReachabilityScopeLinkRegistry(
            JdbcConnectionFactory connections,
            boolean migrate
    ) throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresFindingReachabilityScopeLinkRegistry(
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

    PostgresFindingReachabilityScopeLinkRegistry(
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
        Scope scope = Scope.from(nextState);

        try (Connection connection = connections.open()) {
            beginWriteTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                if (!findingExists(connection, tenantId, findingId)) {
                    connection.commit();
                    return new MutationResult(MutationStatus.FINDING_NOT_FOUND, null);
                }

                FindingReachabilityScopeLink current = loadCurrent(
                        connection, tenantId, findingId, scope);
                if (current == null) {
                    if (expectedRevision != 0) {
                        connection.commit();
                        return new MutationResult(MutationStatus.REVISION_CONFLICT, null);
                    }
                    FindingReachabilityScopeLink created = materialize(findingId, 1, nextState);
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

                FindingReachabilityScopeLink updated = materialize(
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
                            "PostgreSQL Finding reachability-scope revision failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL Finding reachability-scope transaction",
                    exception
            );
        }
    }

    @Override
    public CurrentLookup current(
            UUID findingId,
            OriginScope originScope,
            String originLabel,
            TransportProtocol transportProtocol,
            Integer targetPort
    ) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        Scope scope = Scope.of(originScope, originLabel, transportProtocol, targetPort);
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            if (!findingExists(connection, tenantId, findingId)) {
                return new CurrentLookup(false, null);
            }
            return new CurrentLookup(
                    true,
                    loadCurrent(connection, tenantId, findingId, scope)
            );
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL Finding reachability-scope state",
                    exception
            );
        }
    }

    @Override
    public Optional<HistoryPage> history(
            UUID findingId,
            OriginScope originScope,
            String originLabel,
            TransportProtocol transportProtocol,
            Integer targetPort,
            int limit,
            Integer beforeRevision
    ) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        requirePage(limit, beforeRevision);
        Scope scope = Scope.of(originScope, originLabel, transportProtocol, targetPort);
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            if (!findingExists(connection, tenantId, findingId)) {
                return Optional.empty();
            }
            List<FindingReachabilityScopeLink> events = new ArrayList<>();
            String sql = """
                    SELECT id, finding_id, revision, link_status, origin_scope,
                           origin_label_normalized, transport_protocol, target_port,
                           link_method, evidence_sha256, changed_by, change_note, recorded_at
                    FROM rbvm.finding_reachability_scope_link_event
                    WHERE tenant_id = ? AND finding_id = ?
                      AND origin_scope = ? AND origin_label_normalized = ?
                      AND transport_protocol = ? AND target_port_key = ?
                    """ + (beforeRevision == null ? "" : " AND revision < ?")
                    + " ORDER BY revision DESC LIMIT ?";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                int index = 1;
                statement.setObject(index++, tenantId);
                statement.setObject(index++, findingId);
                bindScope(statement, index, scope);
                index += 4;
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
            return Optional.of(new HistoryPage(findingId, scope.scopeKey(), events, next));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL Finding reachability-scope history",
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
            List<FindingReachabilityScopeLink> links = new ArrayList<>();
            String sql = """
                    SELECT link_event_id, finding_id, revision, link_status, origin_scope,
                           origin_label_normalized, transport_protocol, target_port,
                           link_method, evidence_sha256, changed_by, change_note, recorded_at
                    FROM rbvm.current_finding_reachability_scope_link
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
                    "Could not list PostgreSQL Finding reachability-scope states",
                    exception
            );
        }
    }

    public int schemaVersion() {
        return schemaVersion;
    }

    private FindingReachabilityScopeLink materialize(
            UUID findingId,
            int revision,
            ChangeDraft draft
    ) {
        String sha = FindingReachabilityScopeLink.evidenceSha256(
                findingId,
                revision,
                draft.linkStatus(),
                draft.originScope(),
                draft.originLabel(),
                draft.transportProtocol(),
                draft.targetPort()
        );
        return new FindingReachabilityScopeLink(
                UUID.randomUUID(),
                findingId,
                revision,
                draft.linkStatus(),
                draft.originScope(),
                draft.originLabel(),
                draft.transportProtocol(),
                draft.targetPort(),
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
            FindingReachabilityScopeLink event
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.finding_reachability_scope_link_event(
                    id, tenant_id, finding_id, revision, link_status, origin_scope,
                    origin_label_normalized, transport_protocol, target_port, link_method,
                    evidence_sha256, changed_by, change_note, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, event.eventId());
            statement.setObject(2, tenantId);
            statement.setObject(3, event.findingId());
            statement.setInt(4, event.revision());
            statement.setString(5, event.linkStatus().name());
            statement.setString(6, event.originScope().name());
            statement.setString(7, event.originLabel());
            statement.setString(8, event.transportProtocol().name());
            if (event.targetPort() == null) {
                statement.setObject(9, null);
            } else {
                statement.setInt(9, event.targetPort());
            }
            statement.setString(10, event.linkMethod().name());
            statement.setString(11, event.evidenceSha256());
            statement.setString(12, event.changedBy());
            statement.setString(13, event.changeNote());
            statement.setTimestamp(14, Timestamp.from(event.recordedAt()));
            statement.executeUpdate();
        }
    }

    private static FindingReachabilityScopeLink loadCurrent(
            Connection connection,
            UUID tenantId,
            UUID findingId,
            Scope scope
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT link_event_id, finding_id, revision, link_status, origin_scope,
                       origin_label_normalized, transport_protocol, target_port,
                       link_method, evidence_sha256, changed_by, change_note, recorded_at
                FROM rbvm.current_finding_reachability_scope_link
                WHERE tenant_id = ? AND finding_id = ?
                  AND origin_scope = ? AND origin_label_normalized = ?
                  AND transport_protocol = ? AND COALESCE(target_port, 0) = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, findingId);
            bindScope(statement, 3, scope);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? map(rows) : null;
            }
        }
    }

    private static void bindScope(PreparedStatement statement, int index, Scope scope)
            throws SQLException {
        statement.setString(index, scope.originScope().name());
        statement.setString(index + 1, scope.originLabel());
        statement.setString(index + 2, scope.transportProtocol().name());
        statement.setInt(index + 3, scope.targetPortKey());
    }

    private static FindingReachabilityScopeLink map(ResultSet rows) throws SQLException {
        return new FindingReachabilityScopeLink(
                rows.getObject(1, UUID.class),
                rows.getObject(2, UUID.class),
                rows.getInt(3),
                LinkStatus.valueOf(rows.getString(4)),
                OriginScope.valueOf(rows.getString(5)),
                rows.getString(6),
                TransportProtocol.valueOf(rows.getString(7)),
                (Integer) rows.getObject(8),
                LinkMethod.valueOf(rows.getString(9)),
                rows.getString(10).trim(),
                rows.getString(11),
                rows.getString(12),
                rows.getTimestamp(13).toInstant()
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

    private record Scope(
            OriginScope originScope,
            String originLabel,
            TransportProtocol transportProtocol,
            Integer targetPort
    ) {
        private Scope {
            originScope = Objects.requireNonNull(originScope, "originScope");
            originLabel = normalizeLabel(originLabel);
            transportProtocol = Objects.requireNonNull(transportProtocol, "transportProtocol");
            validatePort(transportProtocol, targetPort);
        }

        static Scope from(ChangeDraft draft) {
            return of(
                    draft.originScope(),
                    draft.originLabel(),
                    draft.transportProtocol(),
                    draft.targetPort()
            );
        }

        static Scope of(
                OriginScope originScope,
                String originLabel,
                TransportProtocol transportProtocol,
                Integer targetPort
        ) {
            return new Scope(originScope, originLabel, transportProtocol, targetPort);
        }

        int targetPortKey() {
            return targetPort == null ? 0 : targetPort;
        }

        String scopeKey() {
            return originScope.name() + "|"
                    + originLabel.length() + ":" + originLabel + "|"
                    + transportProtocol.name() + "|"
                    + (targetPort == null ? "" : targetPort);
        }
    }

    private static String normalizeLabel(String value) {
        Objects.requireNonNull(value, "originLabel");
        String trimmed = value.trim();
        if (trimmed.isEmpty() || trimmed.length() > 256 || trimmed.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException("originLabel is blank, invalid, or too long");
        }
        return Normalizer.normalize(trimmed, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }

    private static void validatePort(TransportProtocol protocol, Integer targetPort) {
        if (targetPort != null && (targetPort < 1 || targetPort > 65_535)) {
            throw new IllegalArgumentException("targetPort must be between 1 and 65535 when present");
        }
        if ((protocol == TransportProtocol.TCP || protocol == TransportProtocol.UDP)
                && targetPort == null) {
            throw new IllegalArgumentException("targetPort is required for TCP or UDP scope");
        }
        if (protocol == TransportProtocol.ICMP && targetPort != null) {
            throw new IllegalArgumentException("targetPort must be absent for ICMP scope");
        }
    }
}
