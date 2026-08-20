package io.rbvm.postgres;

import io.rbvm.asset.ManagedAsset;
import io.rbvm.asset.ManagedAsset.ClassificationMethod;
import io.rbvm.asset.ManagedAsset.LifecycleStatus;
import io.rbvm.asset.ManagedAsset.Revision;
import io.rbvm.asset.ManagedAsset.RevisionDraft;
import io.rbvm.asset.ManagedAssetRegistry;
import io.rbvm.asset.ManagedAssetRegistry.MutationResult;
import io.rbvm.asset.ManagedAssetRegistry.MutationStatus;
import io.rbvm.csv.AssetContextCsvEvidence.BusinessCriticality;
import io.rbvm.csv.AssetContextCsvEvidence.Environment;

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
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** PostgreSQL-backed customer asset registry with append-only revisions. */
public final class PostgresManagedAssetRegistry implements ManagedAssetRegistry {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 18;
    private static final long REGISTRY_LOCK = 5_614_430_257_800_214_039L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresManagedAssetRegistry(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresManagedAssetRegistry(
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

    PostgresManagedAssetRegistry(JdbcConnectionFactory connections, int schemaVersion, Clock clock)
            throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.schemaVersion = schemaVersion;
        requireSchemaVersion(schemaVersion);
    }

    @Override
    public MutationResult create(
            UUID managedAssetId,
            String customerAssetKey,
            RevisionDraft initialRevision
    ) throws IOException {
        Objects.requireNonNull(managedAssetId, "managedAssetId");
        Objects.requireNonNull(initialRevision, "initialRevision");
        String normalizedCustomerKey = optionalText(customerAssetKey);

        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                ManagedAsset existing = loadById(connection, tenantId, managedAssetId);
                if (existing != null) {
                    MutationStatus status = existing.currentRevision().revision() == 1
                            && Objects.equals(existing.customerAssetKey(), normalizedCustomerKey)
                            && initialRevision.sameCustomerState(existing.currentRevision())
                            ? MutationStatus.REPLAYED
                            : MutationStatus.ASSET_ID_CONFLICT;
                    connection.commit();
                    return new MutationResult(status, existing);
                }

                if (normalizedCustomerKey != null) {
                    ManagedAsset keyMatch = loadByCustomerKey(
                            connection,
                            tenantId,
                            normalizedCustomerKey
                    );
                    if (keyMatch != null) {
                        connection.commit();
                        return new MutationResult(MutationStatus.CUSTOMER_KEY_CONFLICT, keyMatch);
                    }
                }

                Instant recordedAt = clock.instant();
                insertManagedAsset(
                        connection,
                        tenantId,
                        managedAssetId,
                        normalizedCustomerKey,
                        recordedAt
                );
                Revision revision = materializeRevision(
                        tenantId,
                        managedAssetId,
                        1,
                        initialRevision,
                        recordedAt
                );
                insertRevision(connection, tenantId, revision);
                ManagedAsset created = new ManagedAsset(
                        managedAssetId,
                        normalizedCustomerKey,
                        recordedAt,
                        revision
                );
                connection.commit();
                return new MutationResult(MutationStatus.CREATED, created);
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL managed asset create failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL managed asset transaction",
                    exception
            );
        }
    }

    @Override
    public MutationResult revise(
            UUID managedAssetId,
            int expectedRevision,
            RevisionDraft nextRevision
    ) throws IOException {
        Objects.requireNonNull(managedAssetId, "managedAssetId");
        Objects.requireNonNull(nextRevision, "nextRevision");
        if (expectedRevision < 1) {
            throw new IllegalArgumentException("expectedRevision must be positive");
        }

        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                ManagedAsset existing = loadById(connection, tenantId, managedAssetId);
                if (existing == null) {
                    connection.commit();
                    return new MutationResult(MutationStatus.NOT_FOUND, null);
                }

                int currentRevision = existing.currentRevision().revision();
                if (currentRevision == expectedRevision + 1
                        && nextRevision.sameCustomerState(existing.currentRevision())) {
                    connection.commit();
                    return new MutationResult(MutationStatus.REPLAYED, existing);
                }
                if (currentRevision != expectedRevision) {
                    connection.commit();
                    return new MutationResult(MutationStatus.REVISION_CONFLICT, existing);
                }
                if (nextRevision.sameCustomerState(existing.currentRevision())) {
                    connection.commit();
                    return new MutationResult(MutationStatus.REPLAYED, existing);
                }

                Instant recordedAt = clock.instant();
                Revision revision = materializeRevision(
                        tenantId,
                        managedAssetId,
                        currentRevision + 1,
                        nextRevision,
                        recordedAt
                );
                insertRevision(connection, tenantId, revision);
                ManagedAsset updated = new ManagedAsset(
                        existing.id(),
                        existing.customerAssetKey(),
                        existing.createdAt(),
                        revision
                );
                connection.commit();
                return new MutationResult(MutationStatus.UPDATED, updated);
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL managed asset revision failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL managed asset transaction",
                    exception
            );
        }
    }

    @Override
    public Optional<ManagedAsset> find(UUID managedAssetId) throws IOException {
        Objects.requireNonNull(managedAssetId, "managedAssetId");
        try (Connection connection = connections.open()) {
            UUID tenantId = requireTenant(connection);
            return Optional.ofNullable(loadById(connection, tenantId, managedAssetId));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("Could not read PostgreSQL managed asset", exception);
        }
    }

    public int schemaVersion() {
        return schemaVersion;
    }

    private static void requireSchemaVersion(int version) throws IOException {
        if (version < REQUIRED_SCHEMA_VERSION) {
            throw new IOException(
                    "PostgreSQL schema version " + version
                            + " is older than required version " + REQUIRED_SCHEMA_VERSION);
        }
    }

    private static void beginTransaction(Connection connection) throws SQLException {
        connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
        connection.setAutoCommit(false);
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pg_advisory_xact_lock(?)")) {
            statement.setLong(1, REGISTRY_LOCK);
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
                            "PostgreSQL projection tenant has not been initialized before managed asset access");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static ManagedAsset loadById(
            Connection connection,
            UUID tenantId,
            UUID managedAssetId
    ) throws SQLException, IOException {
        return loadOne(
                connection,
                "managed_asset_id = ?",
                tenantId,
                managedAssetId
        );
    }

    private static ManagedAsset loadByCustomerKey(
            Connection connection,
            UUID tenantId,
            String customerAssetKey
    ) throws SQLException, IOException {
        return loadOne(
                connection,
                "customer_asset_key = ?",
                tenantId,
                customerAssetKey
        );
    }

    private static ManagedAsset loadOne(
            Connection connection,
            String predicate,
            UUID tenantId,
            Object value
    ) throws SQLException, IOException {
        String sql = """
                SELECT managed_asset_id, customer_asset_key, created_at,
                       revision_id, revision, lifecycle_status, display_name, environment,
                       business_service, business_owner, business_criticality,
                       classification_method, guide_contract_id, guide_revision,
                       context_source, evidence_sha256, changed_by, change_note, recorded_at
                FROM rbvm.current_managed_asset
                WHERE tenant_id = ? AND %s
                """.formatted(predicate);
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, value);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) return null;
                try {
                    UUID assetId = rows.getObject(1, UUID.class);
                    Revision revision = new Revision(
                            rows.getObject(4, UUID.class),
                            assetId,
                            rows.getInt(5),
                            LifecycleStatus.valueOf(rows.getString(6)),
                            rows.getString(7),
                            Environment.valueOf(rows.getString(8)),
                            rows.getString(9),
                            rows.getString(10),
                            BusinessCriticality.valueOf(rows.getString(11)),
                            ClassificationMethod.valueOf(rows.getString(12)),
                            rows.getString(13),
                            rows.getObject(14) == null ? null : rows.getInt(14),
                            rows.getString(15),
                            rows.getString(16).trim(),
                            rows.getString(17),
                            rows.getString(18),
                            rows.getTimestamp(19).toInstant()
                    );
                    return new ManagedAsset(
                            assetId,
                            rows.getString(2),
                            rows.getTimestamp(3).toInstant(),
                            revision
                    );
                } catch (IllegalArgumentException exception) {
                    throw new IOException("Persisted managed asset revision is invalid", exception);
                }
            }
        }
    }

    private static void insertManagedAsset(
            Connection connection,
            UUID tenantId,
            UUID managedAssetId,
            String customerAssetKey,
            Instant createdAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.managed_asset(id, tenant_id, customer_asset_key, created_at)
                VALUES (?, ?, ?, ?)
                """)) {
            statement.setObject(1, managedAssetId);
            statement.setObject(2, tenantId);
            statement.setString(3, customerAssetKey);
            statement.setTimestamp(4, Timestamp.from(createdAt));
            statement.executeUpdate();
        }
    }

    private static void insertRevision(
            Connection connection,
            UUID tenantId,
            Revision revision
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.managed_asset_revision(
                    id, tenant_id, managed_asset_id, revision, lifecycle_status, display_name,
                    environment, business_service, business_owner, business_criticality,
                    classification_method, guide_contract_id, guide_revision, context_source,
                    evidence_sha256, changed_by, change_note, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, revision.id());
            statement.setObject(2, tenantId);
            statement.setObject(3, revision.managedAssetId());
            statement.setInt(4, revision.revision());
            statement.setString(5, revision.lifecycleStatus().name());
            statement.setString(6, revision.displayName());
            statement.setString(7, revision.environment().name());
            statement.setString(8, revision.businessService());
            statement.setString(9, revision.businessOwner());
            statement.setString(10, revision.businessCriticality().name());
            statement.setString(11, revision.classificationMethod().name());
            statement.setString(12, revision.guideContractId());
            if (revision.guideRevision() == null) {
                statement.setObject(13, null);
            } else {
                statement.setInt(13, revision.guideRevision());
            }
            statement.setString(14, revision.contextSource());
            statement.setString(15, revision.evidenceSha256());
            statement.setString(16, revision.changedBy());
            statement.setString(17, revision.changeNote());
            statement.setTimestamp(18, Timestamp.from(revision.recordedAt()));
            statement.executeUpdate();
        }
    }

    private static Revision materializeRevision(
            UUID tenantId,
            UUID managedAssetId,
            int revision,
            RevisionDraft draft,
            Instant recordedAt
    ) {
        String evidenceSha256 = evidenceSha256(
                tenantId,
                managedAssetId,
                revision,
                draft,
                recordedAt
        );
        UUID revisionId = deterministicRevisionId(
                tenantId,
                managedAssetId,
                revision,
                evidenceSha256
        );
        return new Revision(
                revisionId,
                managedAssetId,
                revision,
                draft.lifecycleStatus(),
                draft.displayName(),
                draft.environment(),
                draft.businessService(),
                draft.businessOwner(),
                draft.businessCriticality(),
                draft.classificationMethod(),
                draft.guideContractId(),
                draft.guideRevision(),
                ManagedAsset.CONTEXT_SOURCE,
                evidenceSha256,
                draft.changedBy(),
                draft.changeNote(),
                recordedAt
        );
    }

    private static String evidenceSha256(
            UUID tenantId,
            UUID managedAssetId,
            int revision,
            RevisionDraft draft,
            Instant recordedAt
    ) {
        String payload = String.join("\u001F",
                tenantId.toString(),
                managedAssetId.toString(),
                Integer.toString(revision),
                draft.lifecycleStatus().name(),
                draft.displayName(),
                draft.environment().name(),
                draft.businessService(),
                draft.businessOwner(),
                draft.businessCriticality().name(),
                draft.classificationMethod().name(),
                nullable(draft.guideContractId()),
                draft.guideRevision() == null ? "" : draft.guideRevision().toString(),
                ManagedAsset.CONTEXT_SOURCE,
                draft.changedBy(),
                draft.changeNote(),
                recordedAt.toString()
        );
        return HexFormat.of().formatHex(sha256(payload.getBytes(StandardCharsets.UTF_8)));
    }

    private static UUID deterministicRevisionId(
            UUID tenantId,
            UUID managedAssetId,
            int revision,
            String evidenceSha256
    ) {
        byte[] digest = sha256((tenantId + "\u001F" + managedAssetId + "\u001F"
                + revision + "\u001F" + evidenceSha256).getBytes(StandardCharsets.UTF_8));
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

    private static String optionalText(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String nullable(String value) {
        return value == null ? "" : value;
    }

    private static void rollback(Connection connection, Throwable cause) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            cause.addSuppressed(rollbackFailure);
        }
    }
}
