package io.rbvm.postgres;

import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicyActivationEvent.ActivationState;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Transactional append-only PostgreSQL registry for explicit risk-method policy activation. */
public final class PostgresRiskMethodSelectionPolicyActivationStore
        implements RiskMethodSelectionPolicyActivationStore {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 26;
    private static final long INSTALL_LOCK = 7_103_462_819_330_442_781L;

    private final JdbcConnectionFactory connections;
    private final int schemaVersion;

    public PostgresRiskMethodSelectionPolicyActivationStore(
            JdbcConnectionFactory connections,
            boolean migrate
    ) throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        PostgresMigrator migrator = new PostgresMigrator(connections);
        schemaVersion = migrate ? migrator.migrate() : migrator.installedVersion();
        if (schemaVersion < REQUIRED_SCHEMA_VERSION) {
            throw new IOException(
                    "PostgreSQL schema version " + schemaVersion
                            + " is older than required version " + REQUIRED_SCHEMA_VERSION);
        }
    }

    @Override
    public RiskMethodSelectionPolicyActivationInstallResult install(
            RbvmRiskMethodSelectionPolicyActivationEvent event
    ) throws IOException {
        Objects.requireNonNull(event, "event");
        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                StoredActivation sameRevision = existingByRevision(
                        connection,
                        tenantId,
                        event.activationRevision()
                );
                if (sameRevision != null) {
                    RiskMethodSelectionPolicyActivationInstallResult.Status status =
                            sameRevision.eventSha256().equals(event.eventSha256())
                                    && Arrays.equals(
                                            sameRevision.canonicalPayload(),
                                            event.canonicalPayload()
                                    )
                                    ? RiskMethodSelectionPolicyActivationInstallResult.Status.REPLAYED
                                    : RiskMethodSelectionPolicyActivationInstallResult.Status.REVISION_CONFLICT;
                    connection.commit();
                    return outcome(status, event, sameRevision);
                }

                StoredActivation current = currentStored(connection, tenantId);
                if (current != null
                        && event.activationRevision() < current.activationRevision()) {
                    connection.commit();
                    return new RiskMethodSelectionPolicyActivationInstallResult(
                            RiskMethodSelectionPolicyActivationInstallResult.Status.STALE_ACTIVATION_REVISION,
                            event.activationRevision(),
                            event.eventSha256(),
                            current.activationRevision(),
                            current.eventSha256()
                    );
                }

                if (event.activatesPolicy()) {
                    requireExactPolicy(
                            connection,
                            tenantId,
                            event.policyRevision(),
                            event.policySha256()
                    );
                }

                insertActivation(connection, tenantId, event);
                connection.commit();
                return new RiskMethodSelectionPolicyActivationInstallResult(
                        RiskMethodSelectionPolicyActivationInstallResult.Status.INSERTED,
                        event.activationRevision(),
                        event.eventSha256(),
                        event.activationRevision(),
                        event.eventSha256()
                );
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL risk method selection policy activation install failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL risk method selection policy activation transaction",
                    exception
            );
        }
    }

    @Override
    public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByActivationRevision(
            int activationRevision
    ) throws IOException {
        if (activationRevision < 1) {
            throw new IllegalArgumentException("activationRevision must be positive");
        }
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            StoredActivation stored = existingByRevision(connection, tenantId, activationRevision);
            return stored == null ? Optional.empty() : Optional.of(rehydrate(stored));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL risk method selection policy activation by revision",
                    exception
            );
        }
    }

    @Override
    public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> findByEventSha256(
            String eventSha256
    ) throws IOException {
        requireSha(eventSha256, "eventSha256");
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            StoredActivation stored = existingBySha(connection, tenantId, eventSha256);
            return stored == null ? Optional.empty() : Optional.of(rehydrate(stored));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL risk method selection policy activation by SHA",
                    exception
            );
        }
    }

    @Override
    public Optional<RbvmRiskMethodSelectionPolicyActivationEvent> current() throws IOException {
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            StoredActivation stored = currentStored(connection, tenantId);
            return stored == null ? Optional.empty() : Optional.of(rehydrate(stored));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read current PostgreSQL risk method selection policy activation",
                    exception
            );
        }
    }

    public int schemaVersion() {
        return schemaVersion;
    }

    private static void beginTransaction(Connection connection) throws SQLException {
        connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
        connection.setAutoCommit(false);
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pg_advisory_xact_lock(?)")) {
            statement.setLong(1, INSTALL_LOCK);
            statement.execute();
        }
    }

    private static UUID requireTenant(Connection connection) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT id FROM rbvm.tenant WHERE tenant_key = ?")) {
            statement.setString(1, TENANT_KEY);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new IOException(
                            "PostgreSQL projection tenant has not been initialized before risk method selection activation access");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static void requireExactPolicy(
            Connection connection,
            UUID tenantId,
            int policyRevision,
            String policySha256
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT 1
                FROM rbvm.risk_method_selection_policy
                WHERE tenant_id = ?
                  AND revision = ?
                  AND policy_sha256 = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setInt(2, policyRevision);
            statement.setString(3, policySha256);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new IOException(
                            "Exact Risk Method Selection Policy revision and SHA do not exist for activation");
                }
            }
        }
    }

    private static StoredActivation existingByRevision(
            Connection connection,
            UUID tenantId,
            int activationRevision
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, contract_id, semantics, activation_revision, activation_state,
                       policy_revision, policy_sha256, event_sha256,
                       canonical_payload_format, canonical_payload,
                       changed_by, change_note, recorded_at
                FROM rbvm.risk_method_selection_policy_activation_event
                WHERE tenant_id = ? AND activation_revision = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setInt(2, activationRevision);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? storedActivation(rows) : null;
            }
        }
    }

    private static StoredActivation existingBySha(
            Connection connection,
            UUID tenantId,
            String eventSha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, contract_id, semantics, activation_revision, activation_state,
                       policy_revision, policy_sha256, event_sha256,
                       canonical_payload_format, canonical_payload,
                       changed_by, change_note, recorded_at
                FROM rbvm.risk_method_selection_policy_activation_event
                WHERE tenant_id = ? AND event_sha256 = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, eventSha256);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? storedActivation(rows) : null;
            }
        }
    }

    private static StoredActivation currentStored(
            Connection connection,
            UUID tenantId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT activation_event_id, contract_id, semantics, activation_revision,
                       activation_state, policy_revision, policy_sha256, event_sha256,
                       canonical_payload_format, canonical_payload,
                       changed_by, change_note, recorded_at
                FROM rbvm.current_risk_method_selection_policy_activation
                WHERE tenant_id = ?
                """)) {
            statement.setObject(1, tenantId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? storedActivation(rows) : null;
            }
        }
    }

    private static StoredActivation storedActivation(ResultSet rows) throws SQLException {
        Integer policyRevision = (Integer) rows.getObject(6);
        String policySha256 = rows.getString(7);
        return new StoredActivation(
                rows.getObject(1, UUID.class),
                rows.getString(2),
                rows.getString(3),
                rows.getInt(4),
                rows.getString(5),
                policyRevision,
                policySha256 == null ? null : policySha256.trim(),
                rows.getString(8).trim(),
                rows.getString(9),
                rows.getBytes(10),
                rows.getString(11),
                rows.getString(12),
                rows.getTimestamp(13).toInstant()
        );
    }

    private static void insertActivation(
            Connection connection,
            UUID tenantId,
            RbvmRiskMethodSelectionPolicyActivationEvent event
    ) throws SQLException {
        UUID id = UUID.nameUUIDFromBytes((
                RbvmRiskMethodSelectionPolicyActivationEvent.ID + ":"
                        + tenantId + ":" + event.eventSha256()
        ).getBytes(StandardCharsets.UTF_8));
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.risk_method_selection_policy_activation_event(
                    id, tenant_id, contract_id, semantics, activation_revision,
                    activation_state, policy_revision, policy_sha256, event_sha256,
                    canonical_payload_format, canonical_payload,
                    changed_by, change_note, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, id);
            statement.setObject(2, tenantId);
            statement.setString(3, event.contractId());
            statement.setString(4, event.semantics());
            statement.setInt(5, event.activationRevision());
            statement.setString(6, event.activationState().name());
            if (event.policyRevision() == null) statement.setNull(7, java.sql.Types.INTEGER);
            else statement.setInt(7, event.policyRevision());
            if (event.policySha256() == null) statement.setNull(8, java.sql.Types.CHAR);
            else statement.setString(8, event.policySha256());
            statement.setString(9, event.eventSha256());
            statement.setString(
                    10,
                    RbvmRiskMethodSelectionPolicyActivationEvent.CANONICAL_PAYLOAD_FORMAT
            );
            statement.setBytes(11, event.canonicalPayload());
            statement.setString(12, event.changedBy());
            statement.setString(13, event.changeNote());
            statement.setTimestamp(14, Timestamp.from(event.recordedAt()));
            statement.executeUpdate();
        }
    }

    private static RbvmRiskMethodSelectionPolicyActivationEvent rehydrate(
            StoredActivation stored
    ) throws IOException {
        RbvmRiskMethodSelectionPolicyActivationEvent event;
        try {
            event = RbvmRiskMethodSelectionPolicyActivationEvent.rehydrate(
                    stored.activationRevision(),
                    ActivationState.valueOf(stored.activationState()),
                    stored.policyRevision(),
                    stored.policySha256(),
                    stored.changedBy(),
                    stored.changeNote(),
                    stored.recordedAt(),
                    stored.eventSha256()
            );
        } catch (IllegalArgumentException exception) {
            throw new IOException(
                    "Persisted risk method selection policy activation event is invalid",
                    exception
            );
        }
        if (!stored.contractId().equals(event.contractId())
                || !stored.semantics().equals(event.semantics())
                || !stored.canonicalPayloadFormat().equals(
                        RbvmRiskMethodSelectionPolicyActivationEvent.CANONICAL_PAYLOAD_FORMAT)
                || !Arrays.equals(stored.canonicalPayload(), event.canonicalPayload())) {
            throw new IOException(
                    "Persisted risk method selection policy activation canonical payload does not match normalized fields");
        }
        return event;
    }

    private static RiskMethodSelectionPolicyActivationInstallResult outcome(
            RiskMethodSelectionPolicyActivationInstallResult.Status status,
            RbvmRiskMethodSelectionPolicyActivationEvent requested,
            StoredActivation observed
    ) {
        return new RiskMethodSelectionPolicyActivationInstallResult(
                status,
                requested.activationRevision(),
                requested.eventSha256(),
                observed.activationRevision(),
                observed.eventSha256()
        );
    }

    private static void rollback(Connection connection, Exception primary) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            primary.addSuppressed(rollbackFailure);
        }
    }

    private static void requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }

    private record StoredActivation(
            UUID id,
            String contractId,
            String semantics,
            int activationRevision,
            String activationState,
            Integer policyRevision,
            String policySha256,
            String eventSha256,
            String canonicalPayloadFormat,
            byte[] canonicalPayload,
            String changedBy,
            String changeNote,
            java.time.Instant recordedAt
    ) {
    }
}
