package io.rbvm.postgres;

import io.rbvm.csv.CisaKevCatalogSnapshot;
import io.rbvm.csv.CisaKevCsvAnalysisReport;
import io.rbvm.csv.CisaKevCsvAnalyzer;
import io.rbvm.csv.CisaKevCsvEvidence;
import io.rbvm.csv.CisaKevEvidence;
import io.rbvm.csv.ValidationIssue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.Date;
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

/** Transactional persistence boundary for snapshot-bound CISA KEV evidence. */
public final class PostgresCisaKevImporter implements CisaKevImporter {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 11;
    private static final int MAX_PERSISTENCE_ISSUES = 100;
    private static final long IMPORT_LOCK = 6_310_943_448_255_807_173L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresCisaKevImporter(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresCisaKevImporter(
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
    public CisaKevImportResult importFile(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        List<CisaKevCsvEvidence> rows = new ArrayList<>();
        CisaKevCsvAnalysisReport analysis = new CisaKevCsvAnalyzer()
                .analyze(path, 0, rows::add);

        Map<SnapshotKey, SnapshotFingerprint> fileSnapshots = new LinkedHashMap<>();
        Set<SnapshotKey> fileSnapshotConflicts = new HashSet<>();
        for (CisaKevCsvEvidence row : rows) {
            CisaKevCatalogSnapshot snapshot = row.evidence().snapshot();
            SnapshotKey key = SnapshotKey.of(snapshot);
            SnapshotFingerprint fingerprint = SnapshotFingerprint.of(snapshot);
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
                for (CisaKevCsvEvidence row : rows) {
                    SnapshotKey key = SnapshotKey.of(row.evidence().snapshot());
                    UUID vulnerabilityId = fileSnapshotConflicts.contains(key)
                            ? null
                            : resolveTenantVulnerability(
                                    connection,
                                    tenantId,
                                    row.evidence().cveId()
                            );
                    resolvedRows.add(new ResolvedRow(row, vulnerabilityId));
                }

                Map<SnapshotKey, SnapshotResolution> snapshots = new HashMap<>();
                long insertedSnapshots = 0;
                long replayedSnapshots = 0;
                long snapshotConflictGroups = fileSnapshotConflicts.size();

                for (ResolvedRow resolved : resolvedRows) {
                    CisaKevCatalogSnapshot snapshot = resolved.row().evidence().snapshot();
                    SnapshotKey key = SnapshotKey.of(snapshot);
                    if (fileSnapshotConflicts.contains(key)
                            || resolved.vulnerabilityId() == null
                            || snapshots.containsKey(key)) {
                        continue;
                    }

                    StoredSnapshot existing = existingSnapshot(connection, tenantId, key);
                    if (existing != null) {
                        if (existing.fingerprint().equals(SnapshotFingerprint.of(snapshot))) {
                            snapshots.put(key, SnapshotResolution.usable(existing.id()));
                            replayedSnapshots++;
                        } else {
                            snapshots.put(key, SnapshotResolution.conflicted());
                            snapshotConflictGroups++;
                        }
                        continue;
                    }

                    UUID snapshotId = deterministicSnapshotId(tenantId, snapshot);
                    insertSnapshot(connection, tenantId, snapshotId, snapshot, ingestedAt);
                    snapshots.put(key, SnapshotResolution.usable(snapshotId));
                    insertedSnapshots++;
                }

                long insertedEvidence = 0;
                long replayedEvidence = 0;
                long quarantined = 0;
                List<ValidationIssue> issues = new ArrayList<>();

                for (ResolvedRow resolved : resolvedRows) {
                    CisaKevCsvEvidence row = resolved.row();
                    CisaKevEvidence evidence = row.evidence();
                    SnapshotKey key = SnapshotKey.of(evidence.snapshot());

                    if (fileSnapshotConflicts.contains(key)) {
                        quarantined++;
                        addIssue(issues, new ValidationIssue(
                                row.sourceRowNumber(),
                                ValidationIssue.Level.ERROR,
                                "CONFLICTING_KEV_SNAPSHOT_TIMESTAMP",
                                "KEV_Source and KEV_Observed_At identify conflicting catalog snapshots within the same file"
                        ));
                        continue;
                    }

                    if (resolved.vulnerabilityId() == null) {
                        quarantined++;
                        addIssue(issues, new ValidationIssue(
                                row.sourceRowNumber(),
                                ValidationIssue.Level.ERROR,
                                "CVE_NOT_FOUND_IN_TENANT",
                                "CVE_ID is not attached to a canonical finding in the selected tenant"
                        ));
                        continue;
                    }

                    SnapshotResolution snapshot = snapshots.get(key);
                    if (snapshot == null) {
                        throw new SQLException("KEV snapshot resolution is missing for a local CVE row");
                    }
                    if (snapshot.conflict()) {
                        quarantined++;
                        addIssue(issues, new ValidationIssue(
                                row.sourceRowNumber(),
                                ValidationIssue.Level.ERROR,
                                "CONFLICTING_PERSISTED_KEV_SNAPSHOT_TIMESTAMP",
                                "KEV_Source already has a different catalog snapshot at KEV_Observed_At"
                        ));
                        continue;
                    }

                    String evidenceSha256 = evidenceSha256(evidence);
                    String existingSha256 = existingEvidenceSha256(
                            connection,
                            tenantId,
                            resolved.vulnerabilityId(),
                            snapshot.id()
                    );
                    if (existingSha256 != null) {
                        if (existingSha256.equals(evidenceSha256)) {
                            replayedEvidence++;
                        } else {
                            quarantined++;
                            addIssue(issues, new ValidationIssue(
                                    row.sourceRowNumber(),
                                    ValidationIssue.Level.ERROR,
                                    "CONFLICTING_PERSISTED_KEV_EVIDENCE",
                                    "CVE_ID already has different KEV membership evidence for this persisted catalog snapshot"
                            ));
                        }
                        continue;
                    }

                    insertEvidence(
                            connection,
                            tenantId,
                            resolved.vulnerabilityId(),
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
                return new CisaKevImportResult(
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
                    throw PostgresErrors.sanitized("PostgreSQL CISA KEV import failed", sqlException);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL CISA KEV import transaction",
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
                            "PostgreSQL projection tenant has not been initialized before CISA KEV import");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static UUID resolveTenantVulnerability(
            Connection connection,
            UUID tenantId,
            String cveId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT DISTINCT v.id
                FROM rbvm.vulnerability v
                JOIN rbvm.exposure e ON e.vulnerability_id = v.id
                WHERE e.tenant_id = ? AND v.cve_id = ?
                LIMIT 1
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, cveId);
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
                SELECT id, catalog_version, catalog_sha256, catalog_count
                FROM rbvm.cisa_kev_catalog_snapshot
                WHERE tenant_id = ? AND kev_source = ? AND observed_at = ?
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
                        new SnapshotFingerprint(
                                rows.getString(2),
                                rows.getString(3).trim(),
                                rows.getInt(4)
                        )
                );
            }
        }
    }

    private static String existingEvidenceSha256(
            Connection connection,
            UUID tenantId,
            UUID vulnerabilityId,
            UUID snapshotId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT evidence_sha256
                FROM rbvm.cisa_kev_evidence
                WHERE tenant_id = ? AND vulnerability_id = ? AND snapshot_id = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, vulnerabilityId);
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
            CisaKevCatalogSnapshot snapshot,
            Instant ingestedAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.cisa_kev_catalog_snapshot(
                    id, tenant_id, catalog_version, catalog_sha256, catalog_count,
                    kev_source, observed_at, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, snapshotId);
            statement.setObject(2, tenantId);
            statement.setString(3, snapshot.catalogVersion());
            statement.setString(4, snapshot.sha256());
            statement.setInt(5, snapshot.parsedCount());
            statement.setString(6, snapshot.source());
            statement.setTimestamp(7, Timestamp.from(snapshot.observedAt()));
            statement.setTimestamp(8, Timestamp.from(ingestedAt));
            statement.executeUpdate();
        }
    }

    private static void insertEvidence(
            Connection connection,
            UUID tenantId,
            UUID vulnerabilityId,
            UUID snapshotId,
            CisaKevEvidence evidence,
            Instant ingestedAt,
            String evidenceSha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.cisa_kev_evidence(
                    id, tenant_id, vulnerability_id, snapshot_id, kev_status,
                    kev_date_added, kev_due_date, known_ransomware_campaign_use,
                    ingested_at, evidence_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, deterministicEvidenceId(tenantId, evidenceSha256));
            statement.setObject(2, tenantId);
            statement.setObject(3, vulnerabilityId);
            statement.setObject(4, snapshotId);
            statement.setString(5, evidence.status().name());
            if (evidence.dateAdded() == null) {
                statement.setNull(6, java.sql.Types.DATE);
            } else {
                statement.setDate(6, Date.valueOf(evidence.dateAdded()));
            }
            if (evidence.dueDate() == null) {
                statement.setNull(7, java.sql.Types.DATE);
            } else {
                statement.setDate(7, Date.valueOf(evidence.dueDate()));
            }
            if (evidence.ransomwareCampaignUse() == null) {
                statement.setNull(8, java.sql.Types.VARCHAR);
            } else {
                statement.setString(8, evidence.ransomwareCampaignUse().name());
            }
            statement.setTimestamp(9, Timestamp.from(ingestedAt));
            statement.setString(10, evidenceSha256);
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
                throw new SQLException("Catalog state is missing for CISA KEV import tenant");
            }
        }
    }

    private static String evidenceSha256(CisaKevEvidence evidence) {
        CisaKevCatalogSnapshot snapshot = evidence.snapshot();
        String canonical = evidence.cveId() + "\u001F"
                + evidence.status().name() + "\u001F"
                + snapshot.catalogVersion() + "\u001F"
                + snapshot.sha256() + "\u001F"
                + snapshot.parsedCount() + "\u001F"
                + snapshot.source() + "\u001F"
                + snapshot.observedAt() + "\u001F"
                + nullable(evidence.dateAdded()) + "\u001F"
                + nullable(evidence.dueDate()) + "\u001F"
                + nullable(evidence.ransomwareCampaignUse());
        return sha256(canonical);
    }

    private static UUID deterministicSnapshotId(UUID tenantId, CisaKevCatalogSnapshot snapshot) {
        String canonical = snapshot.catalogVersion() + "\u001F"
                + snapshot.sha256() + "\u001F"
                + snapshot.parsedCount() + "\u001F"
                + snapshot.source() + "\u001F"
                + snapshot.observedAt();
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

    private static String nullable(Object value) {
        return value == null ? "" : value.toString();
    }

    private static void addIssue(List<ValidationIssue> issues, ValidationIssue issue) {
        if (issues.size() < MAX_PERSISTENCE_ISSUES) {
            issues.add(issue);
        }
    }

    private static void rollback(Connection connection, Exception original) throws IOException {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private record SnapshotKey(String source, Instant observedAt) {
        private static SnapshotKey of(CisaKevCatalogSnapshot snapshot) {
            return new SnapshotKey(snapshot.source(), snapshot.observedAt());
        }
    }

    private record SnapshotFingerprint(String catalogVersion, String sha256, int catalogCount) {
        private static SnapshotFingerprint of(CisaKevCatalogSnapshot snapshot) {
            return new SnapshotFingerprint(
                    snapshot.catalogVersion(),
                    snapshot.sha256(),
                    snapshot.parsedCount()
            );
        }
    }

    private record StoredSnapshot(UUID id, SnapshotFingerprint fingerprint) {
    }

    private record SnapshotResolution(UUID id, boolean conflict) {
        private static SnapshotResolution usable(UUID id) {
            return new SnapshotResolution(Objects.requireNonNull(id, "id"), false);
        }

        private static SnapshotResolution conflicted() {
            return new SnapshotResolution(null, true);
        }
    }

    private record ResolvedRow(CisaKevCsvEvidence row, UUID vulnerabilityId) {
    }
}
