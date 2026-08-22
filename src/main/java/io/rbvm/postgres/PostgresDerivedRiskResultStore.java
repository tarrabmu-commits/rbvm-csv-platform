package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDerivedRiskCanonicalResult;
import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Transactional append-only PostgreSQL persistence for canonical derived-risk results. */
public final class PostgresDerivedRiskResultStore implements DerivedRiskResultStore {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 24;
    private static final long INSTALL_LOCK = 3_428_917_504_812_334_291L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresDerivedRiskResultStore(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresDerivedRiskResultStore(
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
                            + " is older than required derived-risk-result version "
                            + REQUIRED_SCHEMA_VERSION
            );
        }
    }

    @Override
    public DerivedRiskResultInstallResult install(RbvmDerivedRiskCanonicalResult result)
            throws IOException {
        Objects.requireNonNull(result, "result");
        RbvmDerivedRiskMethodology.Evaluation evaluation = result.evaluation();
        validateEvaluation(evaluation);

        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                requireExactDecisionInput(connection, tenantId, evaluation);

                RbvmDerivedRiskMethodology.Definition definition = evaluation.definition();
                StoredDerivedRiskResult existing = existingBySnapshotAndMethodology(
                        connection,
                        tenantId,
                        evaluation.inputSnapshotSha256(),
                        definition.methodologyId(),
                        definition.version(),
                        definition.methodologySha256()
                );
                if (existing != null) {
                    boolean replay = matches(existing, result);
                    connection.commit();
                    return new DerivedRiskResultInstallResult(
                            replay
                                    ? DerivedRiskResultInstallResult.Status.REPLAYED
                                    : DerivedRiskResultInstallResult.Status.RESULT_CONFLICT,
                            result.canonicalSha256(),
                            existing.resultSha256()
                    );
                }

                UUID resultId = deterministicResultId(tenantId, result.canonicalSha256());
                insert(connection, tenantId, resultId, result, clock.instant());
                connection.commit();
                return new DerivedRiskResultInstallResult(
                        DerivedRiskResultInstallResult.Status.INSERTED,
                        result.canonicalSha256(),
                        result.canonicalSha256()
                );
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL derived-risk-result install failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL derived-risk-result transaction",
                    exception
            );
        }
    }

    @Override
    public Optional<StoredDerivedRiskResult> findByResultSha256(String resultSha256)
            throws IOException {
        requireSha(resultSha256, "resultSha256");
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            return Optional.ofNullable(existingByResultSha(connection, tenantId, resultSha256));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL derived risk result by canonical identity",
                    exception
            );
        }
    }

    @Override
    public Optional<StoredDerivedRiskResult> findBySnapshotAndMethodology(
            String inputSnapshotSha256,
            String methodologyId,
            String methodologySha256
    ) throws IOException {
        requireSha(inputSnapshotSha256, "inputSnapshotSha256");
        requireSha(methodologySha256, "methodologySha256");
        RbvmDerivedRiskMethodology.Definition definition = implementedDefinition(
                methodologyId,
                methodologySha256
        );
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            return Optional.ofNullable(existingBySnapshotAndMethodology(
                    connection,
                    tenantId,
                    inputSnapshotSha256,
                    definition.methodologyId(),
                    definition.version(),
                    definition.methodologySha256()
            ));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL derived risk result by input/methodology identity",
                    exception
            );
        }
    }

    public int schemaVersion() {
        return schemaVersion;
    }

    private static void validateEvaluation(RbvmDerivedRiskMethodology.Evaluation evaluation) {
        Objects.requireNonNull(evaluation, "evaluation");
        if (!RbvmDecisionInputSnapshot.V3_ID.equals(evaluation.inputContractId())) {
            throw new IllegalArgumentException(
                    "Derived-risk-result persistence accepts only Decision Input Snapshot V3"
            );
        }
        RbvmDerivedRiskMethodology.Definition definition = evaluation.definition();
        implementedDefinition(definition.methodologyId(), definition.methodologySha256());
    }

    private static RbvmDerivedRiskMethodology.Definition implementedDefinition(
            String methodologyId,
            String methodologySha256
    ) {
        RbvmDerivedRiskMethodology methodology = RbvmDerivedRiskMethodologyCatalog.find(methodologyId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Derived risk methodology is not implemented: " + methodologyId
                ));
        RbvmDerivedRiskMethodology.Definition definition = methodology.definition();
        if (!definition.methodologySha256().equals(methodologySha256)) {
            throw new IllegalArgumentException(
                    "Derived risk methodology SHA does not match the implemented identity"
            );
        }
        return definition;
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
                            "PostgreSQL projection tenant has not been initialized before derived-risk access"
                    );
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static void requireExactDecisionInput(
            Connection connection,
            UUID tenantId,
            RbvmDerivedRiskMethodology.Evaluation evaluation
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT contract_id, finding_id
                FROM rbvm.decision_input_snapshot
                WHERE tenant_id = ? AND snapshot_sha256 = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, evaluation.inputSnapshotSha256());
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new IOException(
                            "Derived risk result references an unpersisted Decision Input snapshot"
                    );
                }
                if (!RbvmDecisionInputSnapshot.V3_ID.equals(rows.getString(1))) {
                    throw new IOException(
                            "Derived risk result may reference only persisted Decision Input Snapshot V3"
                    );
                }
                if (!evaluation.findingId().equals(rows.getObject(2, UUID.class))) {
                    throw new IOException(
                            "Derived risk result Finding identity does not match its Decision Input snapshot"
                    );
                }
            }
        }
    }

    private static StoredDerivedRiskResult existingBySnapshotAndMethodology(
            Connection connection,
            UUID tenantId,
            String inputSnapshotSha256,
            String methodologyId,
            int methodologyVersion,
            String methodologySha256
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, input_snapshot_sha256, finding_id,
                       methodology_id, methodology_version, methodology_sha256,
                       result_state, reason_code, numeric_score, numeric_scale, rating,
                       canonical_payload_format, result_sha256, canonical_payload, persisted_at
                FROM rbvm.derived_risk_result
                WHERE tenant_id = ?
                  AND input_snapshot_sha256 = ?
                  AND methodology_id = ?
                  AND methodology_version = ?
                  AND methodology_sha256 = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, inputSnapshotSha256);
            statement.setString(3, methodologyId);
            statement.setInt(4, methodologyVersion);
            statement.setString(5, methodologySha256);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? storedResult(rows) : null;
            }
        }
    }

    private static StoredDerivedRiskResult existingByResultSha(
            Connection connection,
            UUID tenantId,
            String resultSha256
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, input_snapshot_sha256, finding_id,
                       methodology_id, methodology_version, methodology_sha256,
                       result_state, reason_code, numeric_score, numeric_scale, rating,
                       canonical_payload_format, result_sha256, canonical_payload, persisted_at
                FROM rbvm.derived_risk_result
                WHERE tenant_id = ? AND result_sha256 = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, resultSha256);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? storedResult(rows) : null;
            }
        }
    }

    private static StoredDerivedRiskResult storedResult(ResultSet rows) throws SQLException, IOException {
        try {
            return new StoredDerivedRiskResult(
                    rows.getObject(1, UUID.class),
                    rows.getString(2).trim(),
                    rows.getObject(3, UUID.class),
                    rows.getString(4),
                    rows.getInt(5),
                    rows.getString(6).trim(),
                    RbvmDerivedRiskMethodology.ResultState.valueOf(rows.getString(7)),
                    rows.getString(8),
                    rows.getBigDecimal(9),
                    rows.getString(10),
                    rows.getString(11),
                    rows.getString(12),
                    rows.getString(13).trim(),
                    rows.getBytes(14),
                    rows.getTimestamp(15).toInstant()
            );
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new IOException("Persisted derived-risk-result row is invalid", exception);
        }
    }

    private static void insert(
            Connection connection,
            UUID tenantId,
            UUID resultId,
            RbvmDerivedRiskCanonicalResult result,
            Instant persistedAt
    ) throws SQLException {
        RbvmDerivedRiskMethodology.Evaluation evaluation = result.evaluation();
        RbvmDerivedRiskMethodology.Definition definition = evaluation.definition();
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.derived_risk_result(
                    id, tenant_id, input_snapshot_sha256, finding_id,
                    methodology_id, methodology_version, methodology_sha256,
                    result_state, reason_code, numeric_score, numeric_scale, rating,
                    canonical_payload_format, result_sha256, canonical_payload, persisted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, resultId);
            statement.setObject(2, tenantId);
            statement.setString(3, evaluation.inputSnapshotSha256());
            statement.setObject(4, evaluation.findingId());
            statement.setString(5, definition.methodologyId());
            statement.setInt(6, definition.version());
            statement.setString(7, definition.methodologySha256());
            statement.setString(8, evaluation.state().name());
            statement.setString(9, evaluation.reasonCode());
            statement.setBigDecimal(10, evaluation.numericScore());
            statement.setString(11, evaluation.numericScale());
            statement.setString(12, evaluation.rating());
            statement.setString(13, RbvmDerivedRiskCanonicalResult.PAYLOAD_FORMAT);
            statement.setString(14, result.canonicalSha256());
            statement.setBytes(15, result.canonicalPayload());
            statement.setTimestamp(16, Timestamp.from(persistedAt));
            statement.executeUpdate();
        }
    }

    private static boolean matches(
            StoredDerivedRiskResult stored,
            RbvmDerivedRiskCanonicalResult result
    ) {
        RbvmDerivedRiskMethodology.Evaluation evaluation = result.evaluation();
        RbvmDerivedRiskMethodology.Definition definition = evaluation.definition();
        return stored.inputSnapshotSha256().equals(evaluation.inputSnapshotSha256())
                && stored.findingId().equals(evaluation.findingId())
                && stored.methodologyId().equals(definition.methodologyId())
                && stored.methodologyVersion() == definition.version()
                && stored.methodologySha256().equals(definition.methodologySha256())
                && stored.resultState() == evaluation.state()
                && Objects.equals(stored.reasonCode(), evaluation.reasonCode())
                && Objects.equals(stored.numericScore(), evaluation.numericScore())
                && Objects.equals(stored.numericScale(), evaluation.numericScale())
                && Objects.equals(stored.rating(), evaluation.rating())
                && stored.canonicalPayloadFormat().equals(RbvmDerivedRiskCanonicalResult.PAYLOAD_FORMAT)
                && stored.resultSha256().equals(result.canonicalSha256())
                && Arrays.equals(stored.canonicalPayload(), result.canonicalPayload());
    }

    private static UUID deterministicResultId(UUID tenantId, String resultSha256) {
        return UUID.nameUUIDFromBytes(
                ("rbvm-derived-risk-result:" + tenantId + ":" + resultSha256)
                        .getBytes(StandardCharsets.UTF_8)
        );
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private static String requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
        return value;
    }
}
