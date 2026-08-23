package io.rbvm.postgres;

import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding;
import io.rbvm.decision.RbvmActiveRiskMethodExecutionBinding.ResultFamily;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy.MethodFamily;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicy.SelectionRole;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Transactional append-only PostgreSQL store for exact active risk-method execution provenance. */
public final class PostgresActiveRiskMethodExecutionBindingStore
        implements ActiveRiskMethodExecutionBindingStore {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 27;
    private static final long INSTALL_LOCK = 8_419_627_150_364_288_173L;

    private final JdbcConnectionFactory connections;
    private final int schemaVersion;

    public PostgresActiveRiskMethodExecutionBindingStore(
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
    public ActiveRiskMethodExecutionBindingInstallResult install(
            RbvmActiveRiskMethodExecutionBinding binding
    ) throws IOException {
        Objects.requireNonNull(binding, "binding");
        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                StoredBinding existing = existingByExecutionKey(
                        connection,
                        tenantId,
                        binding.activationEventSha256(),
                        binding.inputSnapshotSha256()
                );
                if (existing != null) {
                    ActiveRiskMethodExecutionBindingInstallResult.Status status =
                            existing.bindingSha256().equals(binding.bindingSha256())
                                    && Arrays.equals(
                                            existing.canonicalPayload(),
                                            binding.canonicalPayload()
                                    )
                                    ? ActiveRiskMethodExecutionBindingInstallResult.Status.REPLAYED
                                    : ActiveRiskMethodExecutionBindingInstallResult.Status.EXECUTION_CONFLICT;
                    connection.commit();
                    return new ActiveRiskMethodExecutionBindingInstallResult(
                            status,
                            binding.bindingSha256(),
                            existing.bindingSha256()
                    );
                }

                insertBinding(connection, tenantId, binding);
                connection.commit();
                return new ActiveRiskMethodExecutionBindingInstallResult(
                        ActiveRiskMethodExecutionBindingInstallResult.Status.INSERTED,
                        binding.bindingSha256(),
                        binding.bindingSha256()
                );
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL active risk method execution binding install failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL active risk method execution binding transaction",
                    exception
            );
        }
    }

    @Override
    public Optional<RbvmActiveRiskMethodExecutionBinding> findByBindingSha256(
            String bindingSha256
    ) throws IOException {
        requireSha(bindingSha256, "bindingSha256");
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            StoredBinding stored = existingByBindingSha(connection, tenantId, bindingSha256);
            return stored == null ? Optional.empty() : Optional.of(rehydrate(stored));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL active risk method execution binding by SHA",
                    exception
            );
        }
    }

    @Override
    public Optional<RbvmActiveRiskMethodExecutionBinding> findByActivationAndInput(
            String activationEventSha256,
            String inputSnapshotSha256
    ) throws IOException {
        requireSha(activationEventSha256, "activationEventSha256");
        requireSha(inputSnapshotSha256, "inputSnapshotSha256");
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            StoredBinding stored = existingByExecutionKey(
                    connection,
                    tenantId,
                    activationEventSha256,
                    inputSnapshotSha256
            );
            return stored == null ? Optional.empty() : Optional.of(rehydrate(stored));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL active risk method execution binding by execution identity",
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
                            "PostgreSQL projection tenant has not been initialized before active risk method execution binding access");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static StoredBinding existingByExecutionKey(
            Connection connection,
            UUID tenantId,
            String activationEventSha256,
            String inputSnapshotSha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, contract_id, semantics, activation_revision,
                       activation_event_sha256, policy_revision, policy_sha256,
                       selection_role, method_family, method_id, method_version,
                       method_sha256, input_snapshot_sha256, result_family, result_sha256,
                       canonical_payload_format, canonical_payload, binding_sha256
                FROM rbvm.active_risk_method_execution_binding
                WHERE tenant_id = ?
                  AND activation_event_sha256 = ?
                  AND input_snapshot_sha256 = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, activationEventSha256);
            statement.setString(3, inputSnapshotSha256);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? storedBinding(rows) : null;
            }
        }
    }

    private static StoredBinding existingByBindingSha(
            Connection connection,
            UUID tenantId,
            String bindingSha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, contract_id, semantics, activation_revision,
                       activation_event_sha256, policy_revision, policy_sha256,
                       selection_role, method_family, method_id, method_version,
                       method_sha256, input_snapshot_sha256, result_family, result_sha256,
                       canonical_payload_format, canonical_payload, binding_sha256
                FROM rbvm.active_risk_method_execution_binding
                WHERE tenant_id = ? AND binding_sha256 = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, bindingSha256);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? storedBinding(rows) : null;
            }
        }
    }

    private static StoredBinding storedBinding(ResultSet rows) throws SQLException {
        return new StoredBinding(
                rows.getObject(1, UUID.class),
                rows.getString(2),
                rows.getString(3),
                rows.getInt(4),
                rows.getString(5).trim(),
                rows.getInt(6),
                rows.getString(7).trim(),
                rows.getString(8),
                rows.getString(9),
                rows.getString(10),
                rows.getInt(11),
                rows.getString(12).trim(),
                rows.getString(13).trim(),
                rows.getString(14),
                rows.getString(15).trim(),
                rows.getString(16),
                rows.getBytes(17),
                rows.getString(18).trim()
        );
    }

    private static void insertBinding(
            Connection connection,
            UUID tenantId,
            RbvmActiveRiskMethodExecutionBinding binding
    ) throws SQLException {
        UUID id = UUID.nameUUIDFromBytes((
                RbvmActiveRiskMethodExecutionBinding.ID + ":"
                        + tenantId + ":" + binding.bindingSha256()
        ).getBytes(StandardCharsets.UTF_8));
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.active_risk_method_execution_binding(
                    id, tenant_id, contract_id, semantics,
                    activation_revision, activation_event_sha256,
                    policy_revision, policy_sha256, selection_role,
                    method_family, method_id, method_version, method_sha256,
                    input_snapshot_sha256, result_family, result_sha256,
                    formula_explanation_sha256, derived_result_sha256,
                    canonical_payload_format, canonical_payload, binding_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, id);
            statement.setObject(2, tenantId);
            statement.setString(3, binding.contractId());
            statement.setString(4, binding.semantics());
            statement.setInt(5, binding.activationRevision());
            statement.setString(6, binding.activationEventSha256());
            statement.setInt(7, binding.policyRevision());
            statement.setString(8, binding.policySha256());
            statement.setString(9, binding.selectionRole().name());
            statement.setString(10, binding.methodFamily().name());
            statement.setString(11, binding.methodId());
            statement.setInt(12, binding.methodVersion());
            statement.setString(13, binding.methodSha256());
            statement.setString(14, binding.inputSnapshotSha256());
            statement.setString(15, binding.resultFamily().name());
            statement.setString(16, binding.resultSha256());
            if (binding.resultFamily() == ResultFamily.RBVM_FORMULA_RESULT) {
                statement.setString(17, binding.resultSha256());
                statement.setNull(18, java.sql.Types.CHAR);
            } else {
                statement.setNull(17, java.sql.Types.CHAR);
                statement.setString(18, binding.resultSha256());
            }
            statement.setString(
                    19,
                    RbvmActiveRiskMethodExecutionBinding.CANONICAL_PAYLOAD_FORMAT
            );
            statement.setBytes(20, binding.canonicalPayload());
            statement.setString(21, binding.bindingSha256());
            statement.executeUpdate();
        }
    }

    private static RbvmActiveRiskMethodExecutionBinding rehydrate(StoredBinding stored)
            throws IOException {
        RbvmActiveRiskMethodExecutionBinding binding;
        try {
            binding = RbvmActiveRiskMethodExecutionBinding.rehydrate(
                    stored.activationRevision(),
                    stored.activationEventSha256(),
                    stored.policyRevision(),
                    stored.policySha256(),
                    SelectionRole.valueOf(stored.selectionRole()),
                    MethodFamily.valueOf(stored.methodFamily()),
                    stored.methodId(),
                    stored.methodVersion(),
                    stored.methodSha256(),
                    stored.inputSnapshotSha256(),
                    ResultFamily.valueOf(stored.resultFamily()),
                    stored.resultSha256(),
                    stored.bindingSha256()
            );
        } catch (IllegalArgumentException exception) {
            throw new IOException("Persisted active risk method execution binding is invalid", exception);
        }
        if (!stored.contractId().equals(binding.contractId())
                || !stored.semantics().equals(binding.semantics())
                || !stored.canonicalPayloadFormat().equals(
                        RbvmActiveRiskMethodExecutionBinding.CANONICAL_PAYLOAD_FORMAT)
                || !Arrays.equals(stored.canonicalPayload(), binding.canonicalPayload())) {
            throw new IOException(
                    "Persisted active risk method execution binding canonical payload does not match normalized fields");
        }
        return binding;
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

    private record StoredBinding(
            UUID id,
            String contractId,
            String semantics,
            int activationRevision,
            String activationEventSha256,
            int policyRevision,
            String policySha256,
            String selectionRole,
            String methodFamily,
            String methodId,
            int methodVersion,
            String methodSha256,
            String inputSnapshotSha256,
            String resultFamily,
            String resultSha256,
            String canonicalPayloadFormat,
            byte[] canonicalPayload,
            String bindingSha256
    ) {
    }
}
