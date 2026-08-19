package io.rbvm.postgres;

import io.rbvm.csv.BusinessImpactCsvAnalysisReport;
import io.rbvm.csv.BusinessImpactCsvAnalyzer;
import io.rbvm.csv.BusinessImpactCsvEvidence;
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

/** Transactional persistence boundary for independent BUSINESS_IMPACT_CSV_V1 evidence. */
public final class PostgresBusinessImpactImporter implements BusinessImpactImporter {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 15;
    private static final int MAX_PERSISTENCE_ISSUES = 100;
    private static final long IMPORT_LOCK = 7_114_293_805_246_013_922L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresBusinessImpactImporter(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresBusinessImpactImporter(JdbcConnectionFactory connections, boolean migrate, Clock clock)
            throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        this.clock = Objects.requireNonNull(clock, "clock");
        PostgresMigrator migrator = new PostgresMigrator(connections);
        schemaVersion = migrate ? migrator.migrate() : migrator.installedVersion();
        if (schemaVersion < REQUIRED_SCHEMA_VERSION) {
            throw new IOException("PostgreSQL schema version " + schemaVersion
                    + " is older than required version " + REQUIRED_SCHEMA_VERSION);
        }
    }

    @Override
    public BusinessImpactImportResult importFile(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        List<BusinessImpactCsvEvidence> rows = new ArrayList<>();
        BusinessImpactCsvAnalysisReport analysis = new BusinessImpactCsvAnalyzer()
                .analyze(path, 0, rows::add);

        Map<SnapshotKey, String> fileSnapshots = new LinkedHashMap<>();
        Set<SnapshotKey> fileSnapshotConflicts = new HashSet<>();
        for (BusinessImpactCsvEvidence row : rows) {
            SnapshotKey key = SnapshotKey.of(row);
            String first = fileSnapshots.putIfAbsent(key, row.impactSourceSha256());
            if (first != null && !first.equals(row.impactSourceSha256())) {
                fileSnapshotConflicts.add(key);
            }
        }

        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                Instant ingestedAt = clock.instant();
                List<ResolvedRow> resolvedRows = new ArrayList<>(rows.size());
                for (BusinessImpactCsvEvidence row : rows) {
                    UUID assetId = fileSnapshotConflicts.contains(SnapshotKey.of(row))
                            ? null : resolveTenantAsset(connection, tenantId, row);
                    resolvedRows.add(new ResolvedRow(row, assetId));
                }

                Map<SnapshotKey, SnapshotResolution> snapshots = new HashMap<>();
                long insertedSnapshots = 0;
                long replayedSnapshots = 0;
                long snapshotConflictGroups = fileSnapshotConflicts.size();
                for (ResolvedRow resolved : resolvedRows) {
                    BusinessImpactCsvEvidence evidence = resolved.evidence();
                    SnapshotKey key = SnapshotKey.of(evidence);
                    if (fileSnapshotConflicts.contains(key)
                            || resolved.assetId() == null
                            || snapshots.containsKey(key)) {
                        continue;
                    }
                    StoredSnapshot existing = existingSnapshot(connection, tenantId, key);
                    if (existing != null) {
                        if (existing.sourceSha256().equals(evidence.impactSourceSha256())) {
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
                    BusinessImpactCsvEvidence evidence = resolved.evidence();
                    SnapshotKey key = SnapshotKey.of(evidence);
                    if (fileSnapshotConflicts.contains(key)) {
                        quarantined++;
                        addIssue(issues, issue(evidence, "CONFLICTING_BUSINESS_IMPACT_SNAPSHOT_TIMESTAMP",
                                "Impact_Source and Impact_Observed_At identify conflicting source artifacts within the same file"));
                        continue;
                    }
                    if (resolved.assetId() == null) {
                        quarantined++;
                        addIssue(issues, issue(evidence, "ASSET_NOT_FOUND_IN_TENANT",
                                "Asset identity does not resolve to an existing canonical asset in the selected tenant and source profile"));
                        continue;
                    }
                    SnapshotResolution snapshot = snapshots.get(key);
                    if (snapshot == null) {
                        throw new SQLException("Business Impact snapshot resolution is missing for a local asset row");
                    }
                    if (snapshot.conflict()) {
                        quarantined++;
                        addIssue(issues, issue(evidence,
                                "CONFLICTING_PERSISTED_BUSINESS_IMPACT_SNAPSHOT_TIMESTAMP",
                                "Impact_Source already has different source bytes at Impact_Observed_At"));
                        continue;
                    }

                    String evidenceSha256 = evidenceSha256(evidence);
                    String existingSha = existingEvidenceSha256(
                            connection, tenantId, resolved.assetId(), snapshot.id(), evidence);
                    if (existingSha != null) {
                        if (existingSha.equals(evidenceSha256)) {
                            replayedEvidence++;
                        } else {
                            quarantined++;
                            addIssue(issues, issue(evidence,
                                    "CONFLICTING_PERSISTED_BUSINESS_IMPACT_EVIDENCE",
                                    "Canonical asset already has different Business Impact evidence for this source snapshot, service, and dimension"));
                        }
                        continue;
                    }
                    insertEvidence(connection, tenantId, resolved.assetId(), snapshot.id(),
                            evidence, ingestedAt, evidenceSha256);
                    insertedEvidence++;
                }

                if (insertedEvidence > 0) {
                    incrementCatalogRevision(connection, tenantId, ingestedAt);
                }
                connection.commit();
                return new BusinessImpactImportResult(
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
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized("PostgreSQL Business Impact import failed", sqlException);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL Business Impact import transaction", exception);
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
                            "PostgreSQL projection tenant has not been initialized before Business Impact import");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static UUID resolveTenantAsset(
            Connection connection,
            UUID tenantId,
            BusinessImpactCsvEvidence evidence
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
                FROM rbvm.business_impact_snapshot
                WHERE tenant_id = ? AND impact_source = ? AND observed_at = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, key.source());
            statement.setTimestamp(3, Timestamp.from(key.observedAt()));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) return null;
                return new StoredSnapshot(rows.getObject(1, UUID.class), rows.getString(2).trim());
            }
        }
    }

    private static String existingEvidenceSha256(
            Connection connection,
            UUID tenantId,
            UUID assetId,
            UUID snapshotId,
            BusinessImpactCsvEvidence evidence
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT evidence_sha256
                FROM rbvm.business_impact_evidence
                WHERE tenant_id = ?
                  AND asset_id = ?
                  AND snapshot_id = ?
                  AND business_service_normalized = ?
                  AND impact_dimension = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, assetId);
            statement.setObject(3, snapshotId);
            statement.setString(4, evidence.normalizedBusinessService());
            statement.setString(5, evidence.impactDimension().name());
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getString(1).trim() : null;
            }
        }
    }

    private static void insertSnapshot(
            Connection connection,
            UUID tenantId,
            UUID snapshotId,
            BusinessImpactCsvEvidence evidence,
            Instant ingestedAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.business_impact_snapshot(
                    id, tenant_id, impact_source, source_sha256, observed_at, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, snapshotId);
            statement.setObject(2, tenantId);
            statement.setString(3, evidence.impactSource());
            statement.setString(4, evidence.impactSourceSha256());
            statement.setTimestamp(5, Timestamp.from(evidence.impactObservedAt()));
            statement.setTimestamp(6, Timestamp.from(ingestedAt));
            statement.executeUpdate();
        }
    }

    private static void insertEvidence(
            Connection connection,
            UUID tenantId,
            UUID assetId,
            UUID snapshotId,
            BusinessImpactCsvEvidence evidence,
            Instant ingestedAt,
            String evidenceSha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.business_impact_evidence(
                    id, tenant_id, asset_id, snapshot_id, asset_identity_basis,
                    asset_name_observed, asset_source_id, business_service,
                    business_service_normalized, impact_dimension, impact_level,
                    impact_method, impact_statement, ingested_at, evidence_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, deterministicEvidenceId(tenantId, evidenceSha256));
            statement.setObject(2, tenantId);
            statement.setObject(3, assetId);
            statement.setObject(4, snapshotId);
            statement.setString(5, evidence.assetIdentityBasis().name());
            statement.setString(6, evidence.assetObservedName());
            statement.setString(7, evidence.assetSourceId().isBlank() ? null : evidence.assetSourceId());
            statement.setString(8, evidence.businessService());
            statement.setString(9, evidence.normalizedBusinessService());
            statement.setString(10, evidence.impactDimension().name());
            statement.setString(11, evidence.impactLevel().name());
            statement.setString(12, evidence.impactMethod().name());
            statement.setString(13, evidence.impactStatement());
            statement.setTimestamp(14, Timestamp.from(ingestedAt));
            statement.setString(15, evidenceSha256);
            statement.executeUpdate();
        }
    }

    private static void incrementCatalogRevision(Connection connection, UUID tenantId, Instant at)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE rbvm.catalog_state
                SET revision = revision + 1, updated_at = ?
                WHERE tenant_id = ?
                """)) {
            statement.setTimestamp(1, Timestamp.from(at));
            statement.setObject(2, tenantId);
            if (statement.executeUpdate() != 1) {
                throw new SQLException("Catalog state is missing for Business Impact import tenant");
            }
        }
    }

    private static String evidenceSha256(BusinessImpactCsvEvidence evidence) {
        return sha256(evidence.sourceProfileKey() + "\u001F"
                + evidence.assetIdentityBasis().name() + "\u001F"
                + evidence.normalizedAssetIdentityKey() + "\u001F"
                + evidence.normalizedAssetName() + "\u001F"
                + evidence.assetSourceId() + "\u001F"
                + evidence.normalizedBusinessService() + "\u001F"
                + evidence.impactDimension().name() + "\u001F"
                + evidence.impactLevel().name() + "\u001F"
                + evidence.impactMethod().name() + "\u001F"
                + evidence.impactStatement() + "\u001F"
                + evidence.impactSource() + "\u001F"
                + evidence.impactObservedAt() + "\u001F"
                + evidence.impactSourceSha256());
    }

    private static UUID deterministicSnapshotId(UUID tenantId, BusinessImpactCsvEvidence evidence) {
        return deterministicId(tenantId, sha256(evidence.impactSource() + "\u001F"
                + evidence.impactObservedAt() + "\u001F" + evidence.impactSourceSha256()));
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
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    private static ValidationIssue issue(BusinessImpactCsvEvidence evidence, String code, String message) {
        return new ValidationIssue(evidence.sourceRowNumber(), ValidationIssue.Level.ERROR, code, message);
    }

    private static void addIssue(List<ValidationIssue> issues, ValidationIssue issue) {
        if (issues.size() < MAX_PERSISTENCE_ISSUES) issues.add(issue);
    }

    private static void rollback(Connection connection, Throwable cause) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            cause.addSuppressed(rollbackFailure);
        }
    }

    private record SnapshotKey(String source, Instant observedAt) {
        private static SnapshotKey of(BusinessImpactCsvEvidence evidence) {
            return new SnapshotKey(evidence.impactSource(), evidence.impactObservedAt());
        }
    }

    private record StoredSnapshot(UUID id, String sourceSha256) {}
    private record SnapshotResolution(UUID id, boolean conflict) {
        private static SnapshotResolution usable(UUID id) { return new SnapshotResolution(id, false); }
        private static SnapshotResolution conflicted() { return new SnapshotResolution(null, true); }
    }
    private record ResolvedRow(BusinessImpactCsvEvidence evidence, UUID assetId) {}
}
