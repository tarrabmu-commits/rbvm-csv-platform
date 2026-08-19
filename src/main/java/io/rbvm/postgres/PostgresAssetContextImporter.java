package io.rbvm.postgres;

import io.rbvm.csv.AssetContextCsvAnalysisReport;
import io.rbvm.csv.AssetContextCsvAnalyzer;
import io.rbvm.csv.AssetContextCsvEvidence;
import io.rbvm.csv.ValidationIssue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Transactional persistence boundary for independent ASSET_CONTEXT_CSV_V1 evidence. */
public final class PostgresAssetContextImporter implements AssetContextImporter {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 13;
    private static final int MAX_PERSISTENCE_ISSUES = 100;
    private static final long IMPORT_LOCK = 6_211_486_523_407_119_143L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresAssetContextImporter(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresAssetContextImporter(
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
    public AssetContextImportResult importFile(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        List<AssetContextCsvEvidence> rows = new ArrayList<>();
        AssetContextCsvAnalysisReport analysis = new AssetContextCsvAnalyzer()
                .analyze(path, 0, rows::add);

        Map<SnapshotKey, SnapshotFingerprint> fileSnapshots = new LinkedHashMap<>();
        Set<SnapshotKey> fileSnapshotConflicts = new HashSet<>();
        for (AssetContextCsvEvidence row : rows) {
            SnapshotKey key = SnapshotKey.of(row);
            SnapshotFingerprint fingerprint = SnapshotFingerprint.of(row);
            SnapshotFingerprint first = fileSnapshots.putIfAbsent(key, fingerprint);
            if (first != null && !first.equals(fingerprint)) {
                fileSnapshotConflicts.add(key);
            }
        }

        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                Instant ingestedAt = clock.instant();
                List<ResolvedRow> resolvedRows = new ArrayList<>(rows.size());
                for (AssetContextCsvEvidence row : rows) {
                    SnapshotKey key = SnapshotKey.of(row);
                    UUID assetId = fileSnapshotConflicts.contains(key)
                            ? null : resolveTenantAsset(connection, tenantId, row);
                    resolvedRows.add(new ResolvedRow(row, assetId));
                }

                Map<SnapshotKey, SnapshotResolution> snapshots = new HashMap<>();
                long insertedSnapshots = 0;
                long replayedSnapshots = 0;
                long snapshotConflictGroups = fileSnapshotConflicts.size();

                for (ResolvedRow resolved : resolvedRows) {
                    AssetContextCsvEvidence evidence = resolved.evidence();
                    SnapshotKey key = SnapshotKey.of(evidence);
                    if (fileSnapshotConflicts.contains(key)
                            || resolved.assetId() == null
                            || snapshots.containsKey(key)) {
                        continue;
                    }

                    StoredSnapshot existing = existingSnapshot(connection, tenantId, key);
                    if (existing != null) {
                        if (existing.fingerprint().equals(SnapshotFingerprint.of(evidence))) {
                            snapshots.put(key, SnapshotResolution.usable(existing.id()));
                            replayedSnapshots++;
                        } else {
                            snapshots.put(key, SnapshotResolution.conflicted());
                            snapshotConflictGroups++;
                        }
                        continue;
                    }

                    UUID snapshotId = deterministicSnapshotId(tenantId, evidence);
                    insertSnapshot(connection, tenantId, snapshotId, evidence, ingestedAt);
                    snapshots.put(key, SnapshotResolution.usable(snapshotId));
                    insertedSnapshots++;
                }

                long insertedEvidence = 0;
                long replayedEvidence = 0;
                long quarantined = 0;
                List<ValidationIssue> issues = new ArrayList<>();

                for (ResolvedRow resolved : resolvedRows) {
                    AssetContextCsvEvidence evidence = resolved.evidence();
                    SnapshotKey key = SnapshotKey.of(evidence);

                    if (fileSnapshotConflicts.contains(key)) {
                        quarantined++;
                        addIssue(issues, new ValidationIssue(
                                evidence.sourceRowNumber(),
                                ValidationIssue.Level.ERROR,
                                "CONFLICTING_ASSET_CONTEXT_SNAPSHOT_TIMESTAMP",
                                "Context_Source and Context_Observed_At identify conflicting source artifacts within the same file"
                        ));
                        continue;
                    }

                    if (resolved.assetId() == null) {
                        quarantined++;
                        addIssue(issues, new ValidationIssue(
                                evidence.sourceRowNumber(),
                                ValidationIssue.Level.ERROR,
                                "ASSET_NOT_FOUND_IN_TENANT",
                                "Asset identity does not resolve to an existing canonical asset in the selected tenant and source profile"
                        ));
                        continue;
                    }

                    SnapshotResolution snapshot = snapshots.get(key);
                    if (snapshot == null) {
                        throw new SQLException("Asset context snapshot resolution is missing for a local asset row");
                    }
                    if (snapshot.conflict()) {
                        quarantined++;
                        addIssue(issues, new ValidationIssue(
                                evidence.sourceRowNumber(),
                                ValidationIssue.Level.ERROR,
                                "CONFLICTING_PERSISTED_ASSET_CONTEXT_SNAPSHOT_TIMESTAMP",
                                "Context_Source already has different source bytes at Context_Observed_At"
                        ));
                        continue;
                    }

                    String evidenceSha256 = evidenceSha256(evidence);
                    String existingSha256 = existingEvidenceSha256(
                            connection,
                            tenantId,
                            resolved.assetId(),
                            snapshot.id()
                    );
                    if (existingSha256 != null) {
                        if (existingSha256.equals(evidenceSha256)) {
                            replayedEvidence++;
                        } else {
                            quarantined++;
                            addIssue(issues, new ValidationIssue(
                                    evidence.sourceRowNumber(),
                                    ValidationIssue.Level.ERROR,
                                    "CONFLICTING_PERSISTED_ASSET_CONTEXT_EVIDENCE",
                                    "Canonical asset already has different organizational context evidence for this persisted source snapshot"
                            ));
                        }
                        continue;
                    }

                    insertEvidence(
                            connection,
                            tenantId,
                            resolved.assetId(),
                            snapshot.id(),
                            evidence,
                            ingestedAt,
                            evidenceSha256
                    );
                    insertedEvidence++;
                }

                if (insertedEvidence > 0) {
                    incrementCatalogRevision(connection, tenantId, ingestedAt);
                }
                connection.commit();
                return new AssetContextImportResult(
                        analysis,
                        insertedSnapshots,
                        replayedSnapshots,
                        snapshotConflictGroups,
                        insertedEvidence,
                        replayedEvidence,
                        quarantined,
                        issues
                );
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) {
                    throw ioException;
                }
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized("PostgreSQL asset context import failed", sqlException);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL asset context import transaction",
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
            statement.setLong(1, IMPORT_LOCK);
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
                            "PostgreSQL projection tenant has not been initialized before asset context import");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static UUID resolveTenantAsset(
            Connection connection,
            UUID tenantId,
            AssetContextCsvEvidence evidence
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT a.id
                FROM rbvm.asset a
                JOIN rbvm.source_profile sp
                  ON sp.tenant_id = a.tenant_id
                 AND sp.id = a.source_profile_id
                WHERE a.tenant_id = ?
                  AND sp.external_key = ?
                  AND a.identity_basis = ?
                  AND a.normalized_observed_name = ?
                  AND ((? = 'SOURCE_NAME_ONLY' AND sp.contract_id = 'WAZUH_CSV_V1')
                    OR (? = 'SOURCE_STABLE_ID' AND sp.contract_id = 'WAZUH_CSV_V2'))
                LIMIT 1
                """)) {
            String basis = evidence.assetIdentityBasis().name();
            statement.setObject(1, tenantId);
            statement.setString(2, evidence.sourceProfileKey());
            statement.setString(3, basis);
            statement.setString(4, evidence.normalizedAssetIdentityKey());
            statement.setString(5, basis);
            statement.setString(6, basis);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getObject(1, UUID.class) : null;
            }
        }
    }

    private static StoredSnapshot existingSnapshot(
            Connection connection,
            UUID tenantId,
            SnapshotKey key
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, source_sha256
                FROM rbvm.asset_context_snapshot
                WHERE tenant_id = ? AND context_source = ? AND observed_at = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, key.source());
            statement.setTimestamp(3, Timestamp.from(key.observedAt()));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return null;
                }
                return new StoredSnapshot(
                        rows.getObject(1, UUID.class),
                        new SnapshotFingerprint(rows.getString(2).trim())
                );
            }
        }
    }

    private static String existingEvidenceSha256(
            Connection connection,
            UUID tenantId,
            UUID assetId,
            UUID snapshotId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT evidence_sha256
                FROM rbvm.asset_context_evidence
                WHERE tenant_id = ? AND asset_id = ? AND snapshot_id = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, assetId);
            statement.setObject(3, snapshotId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getString(1).trim() : null;
            }
        }
    }

    private static void insertSnapshot(
            Connection connection,
            UUID tenantId,
            UUID snapshotId,
            AssetContextCsvEvidence evidence,
            Instant ingestedAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.asset_context_snapshot(
                    id, tenant_id, context_source, source_sha256, observed_at, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, snapshotId);
            statement.setObject(2, tenantId);
            statement.setString(3, evidence.contextSource());
            statement.setString(4, evidence.contextSourceSha256());
            statement.setTimestamp(5, Timestamp.from(evidence.contextObservedAt()));
            statement.setTimestamp(6, Timestamp.from(ingestedAt));
            statement.executeUpdate();
        }
    }

    private static void insertEvidence(
            Connection connection,
            UUID tenantId,
            UUID assetId,
            UUID snapshotId,
            AssetContextCsvEvidence evidence,
            Instant ingestedAt,
            String evidenceSha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.asset_context_evidence(
                    id, tenant_id, asset_id, snapshot_id, asset_identity_basis,
                    asset_name_observed, asset_source_id, environment, business_service,
                    business_owner, business_criticality, ingested_at, evidence_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, deterministicEvidenceId(tenantId, evidenceSha256));
            statement.setObject(2, tenantId);
            statement.setObject(3, assetId);
            statement.setObject(4, snapshotId);
            statement.setString(5, evidence.assetIdentityBasis().name());
            statement.setString(6, evidence.assetObservedName());
            statement.setString(7, evidence.assetSourceId().isBlank() ? null : evidence.assetSourceId());
            statement.setString(8, evidence.environment().name());
            statement.setString(9, evidence.businessService());
            statement.setString(10, evidence.businessOwner());
            statement.setString(11, evidence.businessCriticality().name());
            statement.setTimestamp(12, Timestamp.from(ingestedAt));
            statement.setString(13, evidenceSha256);
            statement.executeUpdate();
        }
    }

    private static void incrementCatalogRevision(
            Connection connection,
            UUID tenantId,
            Instant updatedAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE rbvm.catalog_state
                SET revision = revision + 1, updated_at = ?
                WHERE tenant_id = ?
                """)) {
            statement.setTimestamp(1, Timestamp.from(updatedAt));
            statement.setObject(2, tenantId);
            if (statement.executeUpdate() != 1) {
                throw new SQLException("Catalog state is missing for asset context import tenant");
            }
        }
    }

    private static String evidenceSha256(AssetContextCsvEvidence evidence) {
        String canonical = evidence.sourceProfileKey() + "\u001F"
                + evidence.assetIdentityBasis().name() + "\u001F"
                + evidence.normalizedAssetIdentityKey() + "\u001F"
                + evidence.normalizedAssetName() + "\u001F"
                + evidence.assetSourceId() + "\u001F"
                + evidence.environment().name() + "\u001F"
                + evidence.businessService() + "\u001F"
                + evidence.businessOwner() + "\u001F"
                + evidence.businessCriticality().name() + "\u001F"
                + evidence.contextSource() + "\u001F"
                + evidence.contextObservedAt() + "\u001F"
                + evidence.contextSourceSha256();
        return sha256(canonical);
    }

    private static UUID deterministicSnapshotId(
            UUID tenantId,
            AssetContextCsvEvidence evidence
    ) {
        String canonical = evidence.contextSource() + "\u001F"
                + evidence.contextObservedAt() + "\u001F"
                + evidence.contextSourceSha256();
        return deterministicId(tenantId, sha256(canonical));
    }

    private static UUID deterministicEvidenceId(UUID tenantId, String evidenceSha256) {
        return deterministicId(tenantId, evidenceSha256);
    }

    private static UUID deterministicId(UUID tenantId, String semanticSha256) {
        byte[] digest = HexFormat.of().parseHex(sha256(tenantId + "\u001F" + semanticSha256));
        byte[] bytes = Arrays.copyOf(digest, 16);
        bytes[6] = (byte) ((bytes[6] & 0x0f) | 0x80);
        bytes[8] = (byte) ((bytes[8] & 0x3f) | 0x80);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    private static void addIssue(List<ValidationIssue> issues, ValidationIssue issue) {
        if (issues.size() < MAX_PERSISTENCE_ISSUES) {
            issues.add(issue);
        }
    }

    private static void rollback(Connection connection, Throwable cause) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            cause.addSuppressed(rollbackFailure);
        }
    }

    private record SnapshotKey(String source, Instant observedAt) {
        private static SnapshotKey of(AssetContextCsvEvidence evidence) {
            return new SnapshotKey(evidence.contextSource(), evidence.contextObservedAt());
        }
    }

    private record SnapshotFingerprint(String sourceSha256) {
        private static SnapshotFingerprint of(AssetContextCsvEvidence evidence) {
            return new SnapshotFingerprint(evidence.contextSourceSha256());
        }
    }

    private record StoredSnapshot(UUID id, SnapshotFingerprint fingerprint) {
    }

    private record SnapshotResolution(UUID id, boolean conflict) {
        private static SnapshotResolution usable(UUID id) {
            return new SnapshotResolution(id, false);
        }

        private static SnapshotResolution conflicted() {
            return new SnapshotResolution(null, true);
        }
    }

    private record ResolvedRow(AssetContextCsvEvidence evidence, UUID assetId) {
    }
}
