package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmFormulaV1.ResultState;
import io.rbvm.decision.RbvmFormulaV1Explanation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Transactional append-only PostgreSQL persistence for canonical RBVM Formula V1 results. */
public final class PostgresFormulaResultStore implements FormulaResultStore {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 23;
    private static final long INSTALL_LOCK = 4_771_642_840_183_771_119L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresFormulaResultStore(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresFormulaResultStore(
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
                            + " is older than required Formula-result version "
                            + REQUIRED_SCHEMA_VERSION
            );
        }
    }

    @Override
    public FormulaResultInstallResult install(RbvmFormulaV1Explanation explanation)
            throws IOException {
        validateExplanation(explanation);
        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                requireExactDecisionInput(connection, tenantId, explanation);

                StoredFormulaResult existing = existingBySnapshotAndFormula(
                        connection,
                        tenantId,
                        explanation.inputSnapshotSha256(),
                        explanation.formulaSha256()
                );
                if (existing != null) {
                    boolean replay = matchesExplanation(existing, explanation);
                    connection.commit();
                    return new FormulaResultInstallResult(
                            replay
                                    ? FormulaResultInstallResult.Status.REPLAYED
                                    : FormulaResultInstallResult.Status.RESULT_CONFLICT,
                            explanation.canonicalSha256(),
                            existing.explanationSha256()
                    );
                }

                UUID resultId = deterministicResultId(tenantId, explanation.canonicalSha256());
                insert(connection, tenantId, resultId, explanation, clock.instant());
                connection.commit();
                return new FormulaResultInstallResult(
                        FormulaResultInstallResult.Status.INSERTED,
                        explanation.canonicalSha256(),
                        explanation.canonicalSha256()
                );
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL Formula-result install failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL Formula-result transaction",
                    exception
            );
        }
    }

    @Override
    public Optional<StoredFormulaResult> findByExplanationSha256(String explanationSha256)
            throws IOException {
        requireSha(explanationSha256, "explanationSha256");
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            return Optional.ofNullable(existingByExplanationSha(
                    connection,
                    tenantId,
                    explanationSha256
            ));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL Formula result by explanation identity",
                    exception
            );
        }
    }

    @Override
    public Optional<StoredFormulaResult> findBySnapshotAndFormula(
            String inputSnapshotSha256,
            String formulaSha256
    ) throws IOException {
        requireSha(inputSnapshotSha256, "inputSnapshotSha256");
        requireSha(formulaSha256, "formulaSha256");
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            return Optional.ofNullable(existingBySnapshotAndFormula(
                    connection,
                    tenantId,
                    inputSnapshotSha256,
                    formulaSha256
            ));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL Formula result by input/formula identity",
                    exception
            );
        }
    }

    public int schemaVersion() {
        return schemaVersion;
    }

    private static void validateExplanation(RbvmFormulaV1Explanation explanation) {
        Objects.requireNonNull(explanation, "explanation");
        if (!RbvmFormulaV1.FORMULA_ID.equals(explanation.formulaId())
                || explanation.formulaVersion() != RbvmFormulaV1.FORMULA_VERSION
                || !RbvmFormulaV1.FORMULA_SHA256.equals(explanation.formulaSha256())) {
            throw new IllegalArgumentException(
                    "Formula-result persistence accepts only the accepted RBVM Formula V1 identity"
            );
        }
        if (!RbvmDecisionInputSnapshot.V3_ID.equals(explanation.inputContractId())) {
            throw new IllegalArgumentException(
                    "Formula-result persistence accepts only Decision Input Snapshot V3"
            );
        }
        if (!RbvmFormulaV1Explanation.PAYLOAD_FORMAT.equals(
                RbvmFormulaV1Explanation.PAYLOAD_FORMAT
        )) {
            throw new IllegalStateException("Unexpected Formula explanation payload format");
        }
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
                            "PostgreSQL projection tenant has not been initialized before Formula-result access"
                    );
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static void requireExactDecisionInput(
            Connection connection,
            UUID tenantId,
            RbvmFormulaV1Explanation explanation
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT contract_id
                FROM rbvm.decision_input_snapshot
                WHERE tenant_id = ?
                  AND snapshot_sha256 = ?
                  AND finding_id = ?
                  AND methodology_revision = ?
                  AND methodology_policy_sha256 = ?
                  AND evaluated_at = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, explanation.inputSnapshotSha256());
            statement.setObject(3, explanation.findingId());
            statement.setInt(4, explanation.methodologyRevision());
            statement.setString(5, explanation.methodologyPolicySha256());
            statement.setTimestamp(6, Timestamp.from(explanation.evaluatedAt()));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new IOException(
                            "Formula result references an unpersisted or mismatched Decision Input snapshot"
                    );
                }
                String contractId = rows.getString(1);
                if (!RbvmDecisionInputSnapshot.V3_ID.equals(contractId)) {
                    throw new IOException(
                            "Formula result may reference only persisted Decision Input Snapshot V3"
                    );
                }
            }
        }
    }

    private static StoredFormulaResult existingBySnapshotAndFormula(
            Connection connection,
            UUID tenantId,
            String inputSnapshotSha256,
            String formulaSha256
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, input_snapshot_sha256, finding_id, evaluated_at,
                       methodology_revision, methodology_policy_sha256,
                       formula_id, formula_version, formula_sha256,
                       result_state, reason_codes, relative_risk_index,
                       explanation_payload_format, explanation_sha256,
                       explanation_payload, persisted_at
                FROM rbvm.formula_result
                WHERE tenant_id = ?
                  AND input_snapshot_sha256 = ?
                  AND formula_id = ?
                  AND formula_version = ?
                  AND formula_sha256 = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, inputSnapshotSha256);
            statement.setString(3, RbvmFormulaV1.FORMULA_ID);
            statement.setInt(4, RbvmFormulaV1.FORMULA_VERSION);
            statement.setString(5, formulaSha256);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? storedResult(rows) : null;
            }
        }
    }

    private static StoredFormulaResult existingByExplanationSha(
            Connection connection,
            UUID tenantId,
            String explanationSha256
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, input_snapshot_sha256, finding_id, evaluated_at,
                       methodology_revision, methodology_policy_sha256,
                       formula_id, formula_version, formula_sha256,
                       result_state, reason_codes, relative_risk_index,
                       explanation_payload_format, explanation_sha256,
                       explanation_payload, persisted_at
                FROM rbvm.formula_result
                WHERE tenant_id = ? AND explanation_sha256 = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, explanationSha256);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? storedResult(rows) : null;
            }
        }
    }

    private static StoredFormulaResult storedResult(ResultSet rows)
            throws SQLException, IOException {
        Array reasonsArray = rows.getArray(11);
        List<String> reasons = new ArrayList<>();
        if (reasonsArray != null) {
            Object raw = reasonsArray.getArray();
            if (raw instanceof String[] strings) {
                reasons.addAll(Arrays.asList(strings));
            } else if (raw instanceof Object[] values) {
                for (Object value : values) {
                    reasons.add(Objects.toString(value));
                }
            } else {
                throw new IOException("Persisted Formula reason-code array has an invalid shape");
            }
            reasonsArray.free();
        }
        try {
            return new StoredFormulaResult(
                    rows.getObject(1, UUID.class),
                    rows.getString(2).trim(),
                    rows.getObject(3, UUID.class),
                    rows.getTimestamp(4).toInstant(),
                    rows.getInt(5),
                    rows.getString(6).trim(),
                    rows.getString(7),
                    rows.getInt(8),
                    rows.getString(9).trim(),
                    ResultState.valueOf(rows.getString(10)),
                    reasons,
                    rows.getBigDecimal(12),
                    rows.getString(13),
                    rows.getString(14).trim(),
                    rows.getBytes(15),
                    rows.getTimestamp(16).toInstant()
            );
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new IOException("Persisted Formula-result row is invalid", exception);
        }
    }

    private static void insert(
            Connection connection,
            UUID tenantId,
            UUID resultId,
            RbvmFormulaV1Explanation explanation,
            Instant persistedAt
    ) throws SQLException {
        Array reasons = connection.createArrayOf(
                "text",
                explanation.reasonCodes().toArray(String[]::new)
        );
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.formula_result(
                    id, tenant_id, input_snapshot_sha256, finding_id,
                    evaluated_at, methodology_revision, methodology_policy_sha256,
                    formula_id, formula_version, formula_sha256,
                    result_state, reason_codes, relative_risk_index,
                    explanation_payload_format, explanation_sha256,
                    explanation_payload, persisted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, resultId);
            statement.setObject(2, tenantId);
            statement.setString(3, explanation.inputSnapshotSha256());
            statement.setObject(4, explanation.findingId());
            statement.setTimestamp(5, Timestamp.from(explanation.evaluatedAt()));
            statement.setInt(6, explanation.methodologyRevision());
            statement.setString(7, explanation.methodologyPolicySha256());
            statement.setString(8, explanation.formulaId());
            statement.setInt(9, explanation.formulaVersion());
            statement.setString(10, explanation.formulaSha256());
            statement.setString(11, explanation.resultState().name());
            statement.setArray(12, reasons);
            statement.setBigDecimal(13, explanation.finalRiskResult());
            statement.setString(14, RbvmFormulaV1Explanation.PAYLOAD_FORMAT);
            statement.setString(15, explanation.canonicalSha256());
            statement.setBytes(16, explanation.canonicalPayload());
            statement.setTimestamp(17, Timestamp.from(persistedAt));
            statement.executeUpdate();
        } finally {
            reasons.free();
        }
    }

    private static boolean matchesExplanation(
            StoredFormulaResult stored,
            RbvmFormulaV1Explanation explanation
    ) {
        return stored.inputSnapshotSha256().equals(explanation.inputSnapshotSha256())
                && stored.findingId().equals(explanation.findingId())
                && stored.evaluatedAt().equals(explanation.evaluatedAt())
                && stored.methodologyRevision() == explanation.methodologyRevision()
                && stored.methodologyPolicySha256().equals(explanation.methodologyPolicySha256())
                && stored.formulaId().equals(explanation.formulaId())
                && stored.formulaVersion() == explanation.formulaVersion()
                && stored.formulaSha256().equals(explanation.formulaSha256())
                && stored.resultState() == explanation.resultState()
                && stored.reasonCodes().equals(explanation.reasonCodes())
                && Objects.equals(stored.relativeRiskIndex(), explanation.finalRiskResult())
                && stored.explanationPayloadFormat().equals(RbvmFormulaV1Explanation.PAYLOAD_FORMAT)
                && stored.explanationSha256().equals(explanation.canonicalSha256())
                && Arrays.equals(stored.explanationPayload(), explanation.canonicalPayload());
    }

    private static UUID deterministicResultId(UUID tenantId, String explanationSha256) {
        return UUID.nameUUIDFromBytes(
                ("rbvm-formula-result:" + tenantId + ":" + explanationSha256)
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
