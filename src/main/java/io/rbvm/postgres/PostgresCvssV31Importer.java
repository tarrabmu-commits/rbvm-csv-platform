package io.rbvm.postgres;

import io.rbvm.csv.CvssV31BaseEvidence;
import io.rbvm.csv.CvssV31CsvAnalysisReport;
import io.rbvm.csv.CvssV31CsvAnalyzer;
import io.rbvm.csv.CvssV31CsvEvidence;
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
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Transactional persistence boundary for CVSS_V31_CSV_V1. */
public final class PostgresCvssV31Importer implements CvssV31Importer {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 10;
    private static final int MAX_PERSISTENCE_ISSUES = 100;
    private static final long IMPORT_LOCK = 3_812_711_945_001_663_219L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresCvssV31Importer(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresCvssV31Importer(
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
    public CvssV31ImportResult importFile(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        List<CvssV31CsvEvidence> rows = new ArrayList<>();
        CvssV31CsvAnalysisReport analysis = new CvssV31CsvAnalyzer()
                .analyze(path, 0, rows::add);

        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                Instant ingestedAt = clock.instant();
                long inserted = 0;
                long replayed = 0;
                long quarantined = 0;
                List<ValidationIssue> issues = new ArrayList<>();

                for (CvssV31CsvEvidence row : rows) {
                    CvssV31BaseEvidence evidence = row.evidence();
                    UUID vulnerabilityId = resolveTenantVulnerability(
                            connection,
                            tenantId,
                            evidence.cveId()
                    );
                    if (vulnerabilityId == null) {
                        quarantined++;
                        addIssue(issues, new ValidationIssue(
                                row.sourceRowNumber(),
                                ValidationIssue.Level.ERROR,
                                "CVE_NOT_FOUND_IN_TENANT",
                                "CVE_ID is not attached to a canonical finding in the selected tenant"
                        ));
                        continue;
                    }

                    String evidenceSha256 = evidenceSha256(evidence);
                    String existingSha256 = existingEvidenceSha256(
                            connection,
                            tenantId,
                            vulnerabilityId,
                            evidence.source(),
                            evidence.observedAt()
                    );
                    if (existingSha256 != null) {
                        if (existingSha256.equals(evidenceSha256)) {
                            replayed++;
                        } else {
                            quarantined++;
                            addIssue(issues, new ValidationIssue(
                                    row.sourceRowNumber(),
                                    ValidationIssue.Level.ERROR,
                                    "CONFLICTING_PERSISTED_CVSS_EVIDENCE_TIMESTAMP",
                                    "CVE_ID and CVSS_Source already have different CVSS v3.1 Base evidence at CVSS_Observed_At"
                            ));
                        }
                        continue;
                    }

                    insertEvidence(
                            connection,
                            tenantId,
                            vulnerabilityId,
                            evidence,
                            ingestedAt,
                            evidenceSha256
                    );
                    inserted++;
                }

                if (inserted > 0) {
                    incrementCatalogRevision(connection, tenantId, ingestedAt);
                }
                connection.commit();
                return new CvssV31ImportResult(
                        analysis,
                        inserted,
                        replayed,
                        quarantined,
                        issues
                );
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) {
                    throw ioException;
                }
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized("PostgreSQL CVSS v3.1 import failed", sqlException);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL CVSS v3.1 import transaction",
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
                            "PostgreSQL projection tenant has not been initialized before CVSS import");
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

    private static String existingEvidenceSha256(
            Connection connection,
            UUID tenantId,
            UUID vulnerabilityId,
            String source,
            Instant observedAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT evidence_sha256
                FROM rbvm.cvss_v31_base_evidence
                WHERE tenant_id = ?
                  AND vulnerability_id = ?
                  AND cvss_source = ?
                  AND observed_at = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, vulnerabilityId);
            statement.setString(3, source);
            statement.setTimestamp(4, Timestamp.from(observedAt));
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getString(1).trim() : null;
            }
        }
    }

    private static void insertEvidence(
            Connection connection,
            UUID tenantId,
            UUID vulnerabilityId,
            CvssV31BaseEvidence evidence,
            Instant ingestedAt,
            String evidenceSha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.cvss_v31_base_evidence(
                    id, tenant_id, vulnerability_id, cvss_version, base_score, vector,
                    cvss_source, observed_at, ingested_at, evidence_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, deterministicEvidenceId(tenantId, evidenceSha256));
            statement.setObject(2, tenantId);
            statement.setObject(3, vulnerabilityId);
            statement.setString(4, evidence.version());
            statement.setBigDecimal(5, evidence.baseScore());
            statement.setString(6, evidence.canonicalVector());
            statement.setString(7, evidence.source());
            statement.setTimestamp(8, Timestamp.from(evidence.observedAt()));
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
                throw new SQLException("Catalog state is missing for CVSS import tenant");
            }
        }
    }

    private static String evidenceSha256(CvssV31BaseEvidence evidence) {
        String canonical = evidence.cveId() + "\u001F"
                + evidence.version() + "\u001F"
                + evidence.baseScore().toPlainString() + "\u001F"
                + evidence.canonicalVector() + "\u001F"
                + evidence.source() + "\u001F"
                + evidence.observedAt();
        return sha256(canonical);
    }

    private static UUID deterministicEvidenceId(UUID tenantId, String evidenceSha256) {
        String scoped = tenantId + "\u001F" + evidenceSha256;
        byte[] digest = HexFormat.of().parseHex(sha256(scoped));
        byte[] bytes = java.util.Arrays.copyOf(digest, 16);
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
}
