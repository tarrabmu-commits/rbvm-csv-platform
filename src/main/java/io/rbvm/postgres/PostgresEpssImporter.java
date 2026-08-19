package io.rbvm.postgres;

import io.rbvm.csv.EpssCsvAnalysisReport;
import io.rbvm.csv.EpssCsvAnalyzer;
import io.rbvm.csv.EpssCsvEvidence;
import io.rbvm.csv.EpssEvidence;
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
import java.time.LocalDate;
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

/** Transactional persistence boundary for independent EPSS_CSV_V1 evidence. */
public final class PostgresEpssImporter implements EpssImporter {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 12;
    private static final int MAX_PERSISTENCE_ISSUES = 100;
    private static final long IMPORT_LOCK = 7_091_624_835_429_551_307L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresEpssImporter(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresEpssImporter(
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
    public EpssImportResult importFile(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        List<EpssCsvEvidence> rows = new ArrayList<>();
        EpssCsvAnalysisReport analysis = new EpssCsvAnalyzer()
                .analyze(path, 0, rows::add);

        Map<SnapshotKey, SnapshotFingerprint> fileSnapshots = new LinkedHashMap<>();
        Set<SnapshotKey> fileSnapshotConflicts = new HashSet<>();
        for (EpssCsvEvidence row : rows) {
            EpssEvidence evidence = row.evidence();
            SnapshotKey key = SnapshotKey.of(evidence);
            SnapshotFingerprint fingerprint = SnapshotFingerprint.of(evidence);
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
                for (EpssCsvEvidence row : rows) {
                    SnapshotKey key = SnapshotKey.of(row.evidence());
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
                    EpssEvidence evidence = resolved.row().evidence();
                    SnapshotKey key = SnapshotKey.of(evidence);
                    if (fileSnapshotConflicts.contains(key)
                            || resolved.vulnerabilityId() == null
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
                    EpssCsvEvidence row = resolved.row();
                    EpssEvidence evidence = row.evidence();
                    SnapshotKey key = SnapshotKey.of(evidence);

                    if (fileSnapshotConflicts.contains(key)) {
                        quarantined++;
                        addIssue(issues, new ValidationIssue(
                                row.sourceRowNumber(),
                                ValidationIssue.Level.ERROR,
                                "CONFLICTING_EPSS_SNAPSHOT_TIMESTAMP",
                                "EPSS_Source and EPSS_Observed_At identify conflicting score snapshots within the same file"
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
                        throw new SQLException("EPSS snapshot resolution is missing for a local CVE row");
                    }
                    if (snapshot.conflict()) {
                        quarantined++;
                        addIssue(issues, new ValidationIssue(
                                row.sourceRowNumber(),
                                ValidationIssue.Level.ERROR,
                                "CONFLICTING_PERSISTED_EPSS_SNAPSHOT_TIMESTAMP",
                                "EPSS_Source already has a different score snapshot at EPSS_Observed_At"
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
                                    "CONFLICTING_PERSISTED_EPSS_EVIDENCE",
                                    "CVE_ID already has different EPSS probability evidence for this persisted score snapshot"
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
                return new EpssImportResult(
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
                    throw PostgresErrors.sanitized("PostgreSQL EPSS import failed", sqlException);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL EPSS import transaction",
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
                            "PostgreSQL projection tenant has not been initialized before EPSS import");
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
                SELECT id, model_version, score_date, source_sha256
                FROM rbvm.epss_score_snapshot
                WHERE tenant_id = ? AND epss_source = ? AND observed_at = ?
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
                                rows.getDate(3).toLocalDate(),
                                rows.getString(4).trim()
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
                FROM rbvm.epss_evidence
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
            EpssEvidence evidence,
            Instant ingestedAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.epss_score_snapshot(
                    id, tenant_id, model_version, score_date, epss_source,
                    source_sha256, observed_at, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, snapshotId);
            statement.setObject(2, tenantId);
            statement.setString(3, evidence.modelVersion());
            statement.setDate(4, Date.valueOf(evidence.scoreDate()));
            statement.setString(5, evidence.source());
            statement.setString(6, evidence.sourceSha256());
            statement.setTimestamp(7, Timestamp.from(evidence.observedAt()));
            statement.setTimestamp(8, Timestamp.from(ingestedAt));
            statement.executeUpdate();
        }
    }

    private static void insertEvidence(
            Connection connection,
            UUID tenantId,
            UUID vulnerabilityId,
            UUID snapshotId,
            EpssEvidence evidence,
            Instant ingestedAt,
            String evidenceSha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.epss_evidence(
                    id, tenant_id, vulnerability_id, snapshot_id,
                    epss_probability, epss_percentile, ingested_at, evidence_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, deterministicEvidenceId(tenantId, evidenceSha256));
            statement.setObject(2, tenantId);
            statement.setObject(3, vulnerabilityId);
            statement.setObject(4, snapshotId);
            statement.setBigDecimal(5, evidence.probability());
            statement.setBigDecimal(6, evidence.percentile());
            statement.setTimestamp(7, Timestamp.from(ingestedAt));
            statement.setString(8, evidenceSha256);
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
                throw new SQLException("Catalog state is missing for EPSS import tenant");
            }
        }
    }

    private static String evidenceSha256(EpssEvidence evidence) {
        String canonical = evidence.cveId() + "\u001F"
                + evidence.probability().toPlainString() + "\u001F"
                + evidence.percentile().toPlainString() + "\u001F"
                + evidence.modelVersion() + "\u001F"
                + evidence.scoreDate() + "\u001F"
                + evidence.source() + "\u001F"
                + evidence.observedAt() + "\u001F"
                + evidence.sourceSha256();
        return sha256(canonical);
    }

    private static UUID deterministicSnapshotId(UUID tenantId, EpssEvidence evidence) {
        String canonical = evidence.modelVersion() + "\u001F"
                + evidence.scoreDate() + "\u001F"
                + evidence.source() + "\u001F"
                + evidence.observedAt() + "\u001F"
                + evidence.sourceSha256();
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

    private static void rollback(Connection connection, Exception original) throws IOException {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private record SnapshotKey(String source, Instant observedAt) {
        private static SnapshotKey of(EpssEvidence evidence) {
            return new SnapshotKey(evidence.source(), evidence.observedAt());
        }
    }

    private record SnapshotFingerprint(
            String modelVersion,
            LocalDate scoreDate,
            String sourceSha256
    ) {
        private static SnapshotFingerprint of(EpssEvidence evidence) {
            return new SnapshotFingerprint(
                    evidence.modelVersion(),
                    evidence.scoreDate(),
                    evidence.sourceSha256()
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

    private record ResolvedRow(EpssCsvEvidence row, UUID vulnerabilityId) {
    }
}
