package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionMethodologyPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.AmbiguityHandling;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.FreshnessMode;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.LegacyPriorityHandling;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.MissingEvidenceHandling;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.SourceSelectionMode;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.SubjectScope;

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
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Transactional immutable PostgreSQL registry for RBVM decision methodology policies. */
public final class PostgresDecisionMethodologyPolicyStore implements DecisionMethodologyPolicyStore {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 16;
    private static final long INSTALL_LOCK = 8_193_602_174_128_409_731L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresDecisionMethodologyPolicyStore(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresDecisionMethodologyPolicyStore(
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
    public DecisionMethodologyPolicyInstallResult install(RbvmDecisionMethodologyPolicy policy)
            throws IOException {
        Objects.requireNonNull(policy, "policy");
        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                StoredPolicy revisionMatch = existingByRevision(
                        connection,
                        tenantId,
                        policy.revision()
                );
                if (revisionMatch != null) {
                    DecisionMethodologyPolicyInstallResult result;
                    if (revisionMatch.policySha256().equals(policy.policySha256())
                            && Arrays.equals(revisionMatch.canonicalPayload(), policy.canonicalPayload())) {
                        result = result(
                                DecisionMethodologyPolicyInstallResult.Status.REPLAYED,
                                policy,
                                revisionMatch.revision(),
                                revisionMatch.policySha256()
                        );
                    } else {
                        result = result(
                                DecisionMethodologyPolicyInstallResult.Status.REVISION_CONFLICT,
                                policy,
                                revisionMatch.revision(),
                                revisionMatch.policySha256()
                        );
                    }
                    connection.commit();
                    return result;
                }

                UUID policyId = deterministicPolicyId(tenantId, policy.policySha256());
                Instant installedAt = clock.instant();
                insertPolicy(connection, tenantId, policyId, policy, installedAt);
                insertEvidencePolicies(connection, tenantId, policyId, policy);
                connection.commit();
                return result(
                        DecisionMethodologyPolicyInstallResult.Status.INSERTED,
                        policy,
                        policy.revision(),
                        policy.policySha256()
                );
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL methodology policy install failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL methodology policy transaction",
                    exception
            );
        }
    }

    @Override
    public Optional<RbvmDecisionMethodologyPolicy> findByRevision(int revision) throws IOException {
        if (revision < 1) {
            throw new IllegalArgumentException("revision must be positive");
        }
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            StoredPolicy stored = existingByRevision(connection, tenantId, revision);
            if (stored == null) return Optional.empty();

            EnumMap<EvidenceDimension, EvidenceSelectionPolicy> evidencePolicies =
                    loadEvidencePolicies(connection, tenantId, stored.id());
            RbvmDecisionMethodologyPolicy policy;
            try {
                policy = new RbvmDecisionMethodologyPolicy(
                        stored.contractId(),
                        stored.revision(),
                        stored.policySha256(),
                        SubjectScope.valueOf(stored.subjectScope()),
                        MissingEvidenceHandling.valueOf(stored.missingEvidenceHandling()),
                        AmbiguityHandling.valueOf(stored.ambiguityHandling()),
                        LegacyPriorityHandling.valueOf(stored.legacyPriorityHandling()),
                        evidencePolicies
                );
            } catch (IllegalArgumentException exception) {
                throw new IOException("Persisted methodology policy is invalid", exception);
            }
            if (!stored.semantics().equals(policy.semantics())
                    || !stored.canonicalPayloadFormat().equals(
                            RbvmDecisionMethodologyPolicy.CANONICAL_PAYLOAD_FORMAT)
                    || !Arrays.equals(stored.canonicalPayload(), policy.canonicalPayload())) {
                throw new IOException(
                        "Persisted methodology policy canonical payload or semantics do not match normalized policy fields");
            }
            return Optional.of(policy);
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL methodology policy",
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
                            "PostgreSQL projection tenant has not been initialized before methodology policy access");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static StoredPolicy existingByRevision(
            Connection connection,
            UUID tenantId,
            int revision
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, contract_id, semantics, revision, policy_sha256,
                       canonical_payload_format, canonical_payload, subject_scope,
                       missing_evidence_handling, ambiguity_handling, legacy_priority_handling
                FROM rbvm.decision_methodology_policy
                WHERE tenant_id = ? AND contract_id = ? AND revision = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, RbvmDecisionMethodologyPolicy.ID);
            statement.setInt(3, revision);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? storedPolicy(rows) : null;
            }
        }
    }

    private static StoredPolicy storedPolicy(ResultSet rows) throws SQLException {
        return new StoredPolicy(
                rows.getObject(1, UUID.class),
                rows.getString(2),
                rows.getString(3),
                rows.getInt(4),
                rows.getString(5).trim(),
                rows.getString(6),
                rows.getBytes(7),
                rows.getString(8),
                rows.getString(9),
                rows.getString(10),
                rows.getString(11)
        );
    }

    private static void insertPolicy(
            Connection connection,
            UUID tenantId,
            UUID policyId,
            RbvmDecisionMethodologyPolicy policy,
            Instant installedAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.decision_methodology_policy(
                    id, tenant_id, contract_id, semantics, revision, policy_sha256,
                    canonical_payload_format, canonical_payload, subject_scope,
                    missing_evidence_handling, ambiguity_handling, legacy_priority_handling,
                    installed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, policyId);
            statement.setObject(2, tenantId);
            statement.setString(3, policy.contractId());
            statement.setString(4, policy.semantics());
            statement.setInt(5, policy.revision());
            statement.setString(6, policy.policySha256());
            statement.setString(7, RbvmDecisionMethodologyPolicy.CANONICAL_PAYLOAD_FORMAT);
            statement.setBytes(8, policy.canonicalPayload());
            statement.setString(9, policy.subjectScope().name());
            statement.setString(10, policy.missingEvidenceHandling().name());
            statement.setString(11, policy.ambiguityHandling().name());
            statement.setString(12, policy.legacyPriorityHandling().name());
            statement.setTimestamp(13, Timestamp.from(installedAt));
            statement.executeUpdate();
        }
    }

    private static void insertEvidencePolicies(
            Connection connection,
            UUID tenantId,
            UUID policyId,
            RbvmDecisionMethodologyPolicy policy
    ) throws SQLException {
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            EvidenceSelectionPolicy selection = policy.evidencePolicies().get(dimension);
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO rbvm.decision_methodology_evidence_policy(
                        tenant_id, methodology_policy_id, evidence_dimension,
                        source_selection_mode, freshness_mode, maximum_age_seconds
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """)) {
                statement.setObject(1, tenantId);
                statement.setObject(2, policyId);
                statement.setString(3, dimension.name());
                statement.setString(4, selection.sourceSelectionMode().name());
                statement.setString(5, selection.freshnessMode().name());
                statement.setObject(6, selection.maximumAgeSeconds());
                statement.executeUpdate();
            }
            for (String source : selection.sourceAllowlist()) {
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO rbvm.decision_methodology_source_allowlist(
                            tenant_id, methodology_policy_id, evidence_dimension, source_identifier
                        ) VALUES (?, ?, ?, ?)
                        """)) {
                    statement.setObject(1, tenantId);
                    statement.setObject(2, policyId);
                    statement.setString(3, dimension.name());
                    statement.setString(4, source);
                    statement.executeUpdate();
                }
            }
        }
    }

    private static EnumMap<EvidenceDimension, EvidenceSelectionPolicy> loadEvidencePolicies(
            Connection connection,
            UUID tenantId,
            UUID policyId
    ) throws SQLException, IOException {
        EnumMap<EvidenceDimension, EvidenceSelectionPolicy> output =
                new EnumMap<>(EvidenceDimension.class);
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT evidence_dimension, source_selection_mode, freshness_mode,
                       maximum_age_seconds
                FROM rbvm.decision_methodology_evidence_policy
                WHERE tenant_id = ? AND methodology_policy_id = ?
                ORDER BY evidence_dimension
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, policyId);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    EvidenceDimension dimension;
                    SourceSelectionMode sourceSelectionMode;
                    FreshnessMode freshnessMode;
                    try {
                        dimension = EvidenceDimension.valueOf(rows.getString(1));
                        sourceSelectionMode = SourceSelectionMode.valueOf(rows.getString(2));
                        freshnessMode = FreshnessMode.valueOf(rows.getString(3));
                    } catch (IllegalArgumentException exception) {
                        throw new IOException(
                                "Persisted methodology evidence-selection enum is invalid",
                                exception
                        );
                    }
                    Long maximumAge = rows.getObject(4) == null ? null : rows.getLong(4);
                    List<String> sources = loadAllowlist(
                            connection,
                            tenantId,
                            policyId,
                            dimension
                    );
                    output.put(
                            dimension,
                            new EvidenceSelectionPolicy(
                                    dimension,
                                    sourceSelectionMode,
                                    sources,
                                    freshnessMode,
                                    maximumAge
                            )
                    );
                }
            }
        }
        if (output.size() != EvidenceDimension.values().length) {
            throw new IOException(
                    "Persisted methodology policy does not contain all evidence dimensions");
        }
        return output;
    }

    private static List<String> loadAllowlist(
            Connection connection,
            UUID tenantId,
            UUID policyId,
            EvidenceDimension dimension
    ) throws SQLException {
        List<String> sources = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT source_identifier
                FROM rbvm.decision_methodology_source_allowlist
                WHERE tenant_id = ? AND methodology_policy_id = ? AND evidence_dimension = ?
                ORDER BY source_identifier
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, policyId);
            statement.setString(3, dimension.name());
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    sources.add(rows.getString(1));
                }
            }
        }
        return List.copyOf(sources);
    }

    private static DecisionMethodologyPolicyInstallResult result(
            DecisionMethodologyPolicyInstallResult.Status status,
            RbvmDecisionMethodologyPolicy requested,
            int existingRevision,
            String existingPolicySha256
    ) {
        return new DecisionMethodologyPolicyInstallResult(
                status,
                requested.revision(),
                requested.policySha256(),
                existingRevision,
                existingPolicySha256
        );
    }

    private static UUID deterministicPolicyId(UUID tenantId, String policySha256) {
        byte[] digest = sha256((tenantId + "\u001F" + policySha256).getBytes(StandardCharsets.UTF_8));
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

    private static void rollback(Connection connection, Throwable cause) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            cause.addSuppressed(rollbackFailure);
        }
    }

    private record StoredPolicy(
            UUID id,
            String contractId,
            String semantics,
            int revision,
            String policySha256,
            String canonicalPayloadFormat,
            byte[] canonicalPayload,
            String subjectScope,
            String missingEvidenceHandling,
            String ambiguityHandling,
            String legacyPriorityHandling
    ) {
        private StoredPolicy {
            canonicalPayload = canonicalPayload.clone();
        }

        @Override
        public byte[] canonicalPayload() {
            return canonicalPayload.clone();
        }
    }
}
