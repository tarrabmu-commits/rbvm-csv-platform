package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingKind;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.NativeEvidenceKind;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Transactional immutable PostgreSQL persistence for Finding-scoped Decision Input Snapshots. */
public final class PostgresDecisionInputSnapshotStore implements DecisionInputSnapshotStore {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 17;
    private static final long INSTALL_LOCK = 5_216_307_994_612_845_731L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresDecisionInputSnapshotStore(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresDecisionInputSnapshotStore(
            JdbcConnectionFactory connections,
            boolean migrate,
            Clock clock
    ) throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        this.clock = Objects.requireNonNull(clock, "clock");
        PostgresMigrator migrator = new PostgresMigrator(connections);
        schemaVersion = migrate ? migrator.migrate() : migrator.installedVersion();
        if (schemaVersion < REQUIRED_SCHEMA_VERSION) {
            throw new IOException(
                    "PostgreSQL schema version " + schemaVersion
                            + " is older than required version " + REQUIRED_SCHEMA_VERSION);
        }
    }

    @Override
    public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot snapshot)
            throws IOException {
        Objects.requireNonNull(snapshot, "snapshot");
        if (snapshot.isV2() && schemaVersion < 20) {
            throw new IOException(
                    "Decision Input Snapshot V2 requires PostgreSQL schema version 20");
        }
        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                UUID methodologyPolicyId = resolveMethodologyPolicy(
                        connection,
                        tenantId,
                        snapshot.methodologyRevision(),
                        snapshot.methodologyPolicySha256()
                );
                if (methodologyPolicyId == null) {
                    throw new IOException(
                            "Decision input snapshot references an unregistered methodology revision/SHA");
                }
                if (!findingExists(connection, tenantId, snapshot.findingId())) {
                    throw new IOException(
                            "Decision input snapshot Finding_ID does not resolve to an existing canonical finding");
                }

                StoredSnapshot existing = existingEvaluation(
                        connection,
                        tenantId,
                        snapshot.findingId(),
                        methodologyPolicyId,
                        snapshot.evaluatedAt()
                );
                if (existing != null) {
                    DecisionInputSnapshotInstallResult.Status status =
                            existing.snapshotSha256().equals(snapshot.snapshotSha256())
                                    && Arrays.equals(existing.canonicalPayload(), snapshot.canonicalPayload())
                                    ? DecisionInputSnapshotInstallResult.Status.REPLAYED
                                    : DecisionInputSnapshotInstallResult.Status.EVALUATION_CONFLICT;
                    connection.commit();
                    return new DecisionInputSnapshotInstallResult(
                            status,
                            snapshot.snapshotSha256(),
                            existing.snapshotSha256()
                    );
                }

                UUID snapshotId = deterministicSnapshotId(tenantId, snapshot.snapshotSha256());
                insertSnapshot(
                        connection,
                        tenantId,
                        snapshotId,
                        methodologyPolicyId,
                        snapshot,
                        clock.instant()
                );
                insertDimensionsAndReferences(connection, tenantId, snapshotId, snapshot);
                connection.commit();
                return new DecisionInputSnapshotInstallResult(
                        DecisionInputSnapshotInstallResult.Status.INSERTED,
                        snapshot.snapshotSha256(),
                        snapshot.snapshotSha256()
                );
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL decision input snapshot install failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL decision input snapshot transaction",
                    exception
            );
        }
    }

    @Override
    public Optional<RbvmDecisionInputSnapshot> findBySha256(String snapshotSha256)
            throws IOException {
        requireSha(snapshotSha256, "snapshotSha256");
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            StoredSnapshot stored = existingBySha(connection, tenantId, snapshotSha256);
            if (stored == null) return Optional.empty();

            EnumMap<EvidenceDimension, DimensionInput> dimensions =
                    loadDimensions(connection, tenantId, stored.id());
            RbvmDecisionInputSnapshot snapshot;
            try {
                snapshot = new RbvmDecisionInputSnapshot(
                        stored.contractId(),
                        stored.snapshotSha256(),
                        stored.findingId(),
                        stored.methodologyRevision(),
                        stored.methodologyPolicySha256(),
                        stored.evaluatedAt(),
                        dimensions
                );
            } catch (IllegalArgumentException exception) {
                throw new IOException("Persisted decision input snapshot is invalid", exception);
            }
            if (!stored.semantics().equals(snapshot.semantics())
                    || !stored.canonicalPayloadFormat().equals(
                            snapshot.canonicalPayloadFormat())
                    || !Arrays.equals(stored.canonicalPayload(), snapshot.canonicalPayload())) {
                throw new IOException(
                        "Persisted decision input snapshot canonical payload or semantics do not match normalized snapshot fields");
            }
            return Optional.of(snapshot);
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL decision input snapshot",
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
                            "PostgreSQL projection tenant has not been initialized before decision input snapshot access");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static UUID resolveMethodologyPolicy(
            Connection connection,
            UUID tenantId,
            int revision,
            String policySha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id
                FROM rbvm.decision_methodology_policy
                WHERE tenant_id = ?
                  AND contract_id = ?
                  AND revision = ?
                  AND policy_sha256 = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, RbvmDecisionMethodologyPolicy.ID);
            statement.setInt(3, revision);
            statement.setString(4, policySha256);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getObject(1, UUID.class) : null;
            }
        }
    }

    private static boolean findingExists(Connection connection, UUID tenantId, UUID findingId)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT 1 FROM rbvm.exposure WHERE tenant_id = ? AND id = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, findingId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next();
            }
        }
    }

    private static StoredSnapshot existingEvaluation(
            Connection connection,
            UUID tenantId,
            UUID findingId,
            UUID methodologyPolicyId,
            Instant evaluatedAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, finding_id, methodology_revision, methodology_policy_sha256,
                       contract_id, semantics, snapshot_sha256, canonical_payload_format,
                       canonical_payload, evaluated_at
                FROM rbvm.decision_input_snapshot
                WHERE tenant_id = ?
                  AND finding_id = ?
                  AND methodology_policy_id = ?
                  AND evaluated_at = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, findingId);
            statement.setObject(3, methodologyPolicyId);
            statement.setTimestamp(4, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? storedSnapshot(rows) : null;
            }
        }
    }

    private static StoredSnapshot existingBySha(
            Connection connection,
            UUID tenantId,
            String snapshotSha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, finding_id, methodology_revision, methodology_policy_sha256,
                       contract_id, semantics, snapshot_sha256, canonical_payload_format,
                       canonical_payload, evaluated_at
                FROM rbvm.decision_input_snapshot
                WHERE tenant_id = ? AND snapshot_sha256 = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, snapshotSha256);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? storedSnapshot(rows) : null;
            }
        }
    }

    private static StoredSnapshot storedSnapshot(ResultSet rows) throws SQLException {
        return new StoredSnapshot(
                rows.getObject(1, UUID.class),
                rows.getObject(2, UUID.class),
                rows.getInt(3),
                rows.getString(4).trim(),
                rows.getString(5),
                rows.getString(6),
                rows.getString(7).trim(),
                rows.getString(8),
                rows.getBytes(9),
                rows.getTimestamp(10).toInstant()
        );
    }

    private static void insertSnapshot(
            Connection connection,
            UUID tenantId,
            UUID snapshotId,
            UUID methodologyPolicyId,
            RbvmDecisionInputSnapshot snapshot,
            Instant persistedAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.decision_input_snapshot(
                    id, tenant_id, finding_id, methodology_policy_id,
                    methodology_revision, methodology_policy_sha256,
                    contract_id, semantics, snapshot_sha256,
                    canonical_payload_format, canonical_payload,
                    evaluated_at, persisted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, snapshotId);
            statement.setObject(2, tenantId);
            statement.setObject(3, snapshot.findingId());
            statement.setObject(4, methodologyPolicyId);
            statement.setInt(5, snapshot.methodologyRevision());
            statement.setString(6, snapshot.methodologyPolicySha256());
            statement.setString(7, snapshot.contractId());
            statement.setString(8, snapshot.semantics());
            statement.setString(9, snapshot.snapshotSha256());
            statement.setString(10, snapshot.canonicalPayloadFormat());
            statement.setBytes(11, snapshot.canonicalPayload());
            statement.setTimestamp(12, Timestamp.from(snapshot.evaluatedAt()));
            statement.setTimestamp(13, Timestamp.from(persistedAt));
            statement.executeUpdate();
        }
    }

    private void insertDimensionsAndReferences(
            Connection connection,
            UUID tenantId,
            UUID snapshotId,
            RbvmDecisionInputSnapshot snapshot
    ) throws SQLException {
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            DimensionInput input = snapshot.dimensions().get(dimension);
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO rbvm.decision_input_dimension(
                        tenant_id, snapshot_id, evidence_dimension, dimension_state
                    ) VALUES (?, ?, ?, ?)
                    """)) {
                statement.setObject(1, tenantId);
                statement.setObject(2, snapshotId);
                statement.setString(3, dimension.name());
                statement.setString(4, input.state().name());
                statement.executeUpdate();
            }
            for (EvidenceReference reference : input.evidenceReferences()) {
                if (schemaVersion >= 20) {
                    try (PreparedStatement statement = connection.prepareStatement("""
                            INSERT INTO rbvm.decision_input_evidence_reference(
                                tenant_id, snapshot_id, evidence_dimension,
                                native_evidence_kind, evidence_id,
                                evidence_sha256, evidence_source, observed_at,
                                binding_kind, binding_id, binding_sha256,
                                binding_source, binding_observed_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """)) {
                        statement.setObject(1, tenantId);
                        statement.setObject(2, snapshotId);
                        statement.setString(3, dimension.name());
                        statement.setString(4, reference.nativeEvidenceKind().name());
                        statement.setObject(5, reference.evidenceId());
                        statement.setString(6, reference.evidenceSha256());
                        statement.setString(7, reference.evidenceSource());
                        statement.setTimestamp(8, Timestamp.from(reference.observedAt()));
                        BindingReference binding = reference.bindingReference();
                        if (binding == null) {
                            statement.setObject(9, null);
                            statement.setObject(10, null);
                            statement.setObject(11, null);
                            statement.setObject(12, null);
                            statement.setObject(13, null);
                        } else {
                            statement.setString(9, binding.bindingKind().name());
                            statement.setObject(10, binding.bindingId());
                            statement.setString(11, binding.bindingSha256());
                            statement.setString(12, binding.bindingSource());
                            statement.setTimestamp(13, Timestamp.from(binding.recordedAt()));
                        }
                        statement.executeUpdate();
                    }
                } else {
                    try (PreparedStatement statement = connection.prepareStatement("""
                            INSERT INTO rbvm.decision_input_evidence_reference(
                                tenant_id, snapshot_id, evidence_dimension, evidence_id,
                                evidence_sha256, evidence_source, observed_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                            """)) {
                        statement.setObject(1, tenantId);
                        statement.setObject(2, snapshotId);
                        statement.setString(3, dimension.name());
                        statement.setObject(4, reference.evidenceId());
                        statement.setString(5, reference.evidenceSha256());
                        statement.setString(6, reference.evidenceSource());
                        statement.setTimestamp(7, Timestamp.from(reference.observedAt()));
                        statement.executeUpdate();
                    }
                }
            }
        }
    }

    private EnumMap<EvidenceDimension, DimensionInput> loadDimensions(
            Connection connection,
            UUID tenantId,
            UUID snapshotId
    ) throws SQLException, IOException {
        EnumMap<EvidenceDimension, DimensionInput> dimensions =
                new EnumMap<>(EvidenceDimension.class);
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT evidence_dimension, dimension_state
                FROM rbvm.decision_input_dimension
                WHERE tenant_id = ? AND snapshot_id = ?
                ORDER BY evidence_dimension
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, snapshotId);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    EvidenceDimension dimension;
                    DimensionState state;
                    try {
                        dimension = EvidenceDimension.valueOf(rows.getString(1));
                        state = DimensionState.valueOf(rows.getString(2));
                    } catch (IllegalArgumentException exception) {
                        throw new IOException(
                                "Persisted decision-input dimension enum is invalid",
                                exception
                        );
                    }
                    dimensions.put(
                            dimension,
                            new DimensionInput(
                                    dimension,
                                    state,
                                    loadReferences(connection, tenantId, snapshotId, dimension)
                            )
                    );
                }
            }
        }
        if (dimensions.size() != EvidenceDimension.values().length) {
            throw new IOException(
                    "Persisted decision input snapshot does not contain all evidence dimensions");
        }
        return dimensions;
    }

    private List<EvidenceReference> loadReferences(
            Connection connection,
            UUID tenantId,
            UUID snapshotId,
            EvidenceDimension dimension
    ) throws SQLException {
        List<EvidenceReference> references = new ArrayList<>();
        String sql = schemaVersion >= 20
                ? """
                    SELECT native_evidence_kind, evidence_id, evidence_sha256,
                           evidence_source, observed_at,
                           binding_kind, binding_id, binding_sha256,
                           binding_source, binding_observed_at
                    FROM rbvm.decision_input_evidence_reference
                    WHERE tenant_id = ? AND snapshot_id = ? AND evidence_dimension = ?
                    ORDER BY native_evidence_kind, evidence_id
                    """
                : """
                    SELECT evidence_id, evidence_sha256, evidence_source, observed_at
                    FROM rbvm.decision_input_evidence_reference
                    WHERE tenant_id = ? AND snapshot_id = ? AND evidence_dimension = ?
                    ORDER BY evidence_id
                    """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, snapshotId);
            statement.setString(3, dimension.name());
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    if (schemaVersion >= 20) {
                        BindingReference binding = null;
                        String bindingKind = rows.getString(6);
                        if (bindingKind != null) {
                            binding = new BindingReference(
                                    BindingKind.valueOf(bindingKind),
                                    rows.getObject(7, UUID.class),
                                    rows.getString(8).trim(),
                                    rows.getString(9),
                                    rows.getTimestamp(10).toInstant()
                            );
                        }
                        references.add(new EvidenceReference(
                                dimension,
                                NativeEvidenceKind.valueOf(rows.getString(1)),
                                rows.getObject(2, UUID.class),
                                rows.getString(3).trim(),
                                rows.getString(4),
                                rows.getTimestamp(5).toInstant(),
                                binding
                        ));
                    } else {
                        references.add(new EvidenceReference(
                                dimension,
                                rows.getObject(1, UUID.class),
                                rows.getString(2).trim(),
                                rows.getString(3),
                                rows.getTimestamp(4).toInstant()
                        ));
                    }
                }
            }
        }
        return List.copyOf(references);
    }

    private static UUID deterministicSnapshotId(UUID tenantId, String snapshotSha256) {
        byte[] digest = sha256((tenantId + "\u001F" + snapshotSha256).getBytes(StandardCharsets.UTF_8));
        byte[] bytes = Arrays.copyOf(digest, 16);
        bytes[6] = (byte) ((bytes[6] & 0x0f) | 0x80);
        bytes[8] = (byte) ((bytes[8] & 0x3f) | 0x80);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    private static String requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
        return value;
    }

    private static void rollback(Connection connection, Throwable cause) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            cause.addSuppressed(rollbackFailure);
        }
    }

    private record StoredSnapshot(
            UUID id,
            UUID findingId,
            int methodologyRevision,
            String methodologyPolicySha256,
            String contractId,
            String semantics,
            String snapshotSha256,
            String canonicalPayloadFormat,
            byte[] canonicalPayload,
            Instant evaluatedAt
    ) {
        private StoredSnapshot {
            canonicalPayload = canonicalPayload.clone();
        }

        @Override
        public byte[] canonicalPayload() {
            return canonicalPayload.clone();
        }
    }
}
