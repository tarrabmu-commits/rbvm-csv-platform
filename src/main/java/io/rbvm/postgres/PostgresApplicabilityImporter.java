package io.rbvm.postgres;

import io.rbvm.csv.ApplicabilityCsvAnalysisReport;
import io.rbvm.csv.ApplicabilityCsvAnalyzer;
import io.rbvm.csv.ApplicabilityCsvAssessment;
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

/**
 * Transactional persistence boundary for APPLICABILITY_CSV_V1.
 *
 * <p>The parser validates contract semantics first. Accepted rows are then resolved against the
 * tenant-scoped canonical finding (rbvm.exposure.id) and inserted as immutable history. Unknown
 * findings and persisted same-time conflicts are quarantined without aborting the valid rows in the
 * same file. Fatal database errors roll back the entire persistence transaction.</p>
 */
public final class PostgresApplicabilityImporter {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 9;
    private static final int MAX_PERSISTENCE_ISSUES = 100;
    private static final long IMPORT_LOCK = 5_076_543_900_817_244_913L;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;

    public PostgresApplicabilityImporter(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresApplicabilityImporter(
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

    public ApplicabilityImportResult importFile(Path path) throws IOException {
        Objects.requireNonNull(path, "path");

        List<ApplicabilityCsvAssessment> assessments = new ArrayList<>();
        ApplicabilityCsvAnalysisReport analysis = new ApplicabilityCsvAnalyzer()
                .analyze(path, 0, assessments::add);

        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                Instant ingestedAt = clock.instant();
                long inserted = 0;
                long replayed = 0;
                long quarantined = 0;
                List<ValidationIssue> issues = new ArrayList<>();

                for (ApplicabilityCsvAssessment assessment : assessments) {
                    if (!findingExists(connection, tenantId, assessment.findingId())) {
                        quarantined++;
                        addIssue(issues, new ValidationIssue(
                                assessment.sourceRowNumber(),
                                ValidationIssue.Level.ERROR,
                                "FINDING_NOT_FOUND",
                                "Finding_ID does not exist in the selected tenant"
                        ));
                        continue;
                    }

                    String evidenceSha256 = evidenceSha256(assessment);
                    String existingSha256 = existingEvidenceSha256(
                            connection,
                            tenantId,
                            assessment.findingId(),
                            assessment.evaluatedAt()
                    );
                    if (existingSha256 != null) {
                        if (existingSha256.equals(evidenceSha256)) {
                            replayed++;
                        } else {
                            quarantined++;
                            addIssue(issues, new ValidationIssue(
                                    assessment.sourceRowNumber(),
                                    ValidationIssue.Level.ERROR,
                                    "CONFLICTING_PERSISTED_ASSESSMENT_TIMESTAMP",
                                    "Finding_ID already has different applicability evidence at Evaluated_At"
                            ));
                        }
                        continue;
                    }

                    insertAssessment(connection, tenantId, assessment, ingestedAt, evidenceSha256);
                    inserted++;
                }

                if (inserted > 0) {
                    incrementCatalogRevision(connection, tenantId, ingestedAt);
                }
                connection.commit();
                return new ApplicabilityImportResult(
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
                    throw PostgresErrors.sanitized(
                            "PostgreSQL applicability import failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL applicability import transaction",
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
                            "PostgreSQL projection tenant has not been initialized before applicability import");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static boolean findingExists(
            Connection connection,
            UUID tenantId,
            UUID findingId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT 1
                FROM rbvm.exposure
                WHERE tenant_id = ? AND id = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, findingId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next();
            }
        }
    }

    private static String existingEvidenceSha256(
            Connection connection,
            UUID tenantId,
            UUID findingId,
            Instant evaluatedAt
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT evidence_sha256
                FROM rbvm.applicability_assessment
                WHERE tenant_id = ? AND finding_id = ? AND evaluated_at = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, findingId);
            statement.setTimestamp(3, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getString(1).trim() : null;
            }
        }
    }

    private static void insertAssessment(
            Connection connection,
            UUID tenantId,
            ApplicabilityCsvAssessment assessment,
            Instant ingestedAt,
            String evidenceSha256
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.applicability_assessment(
                    id, tenant_id, finding_id, status, reason, evidence_source,
                    evaluated_at, ingested_at, evidence_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, deterministicAssessmentId(evidenceSha256));
            statement.setObject(2, tenantId);
            statement.setObject(3, assessment.findingId());
            statement.setString(4, assessment.status().name());
            statement.setString(5, assessment.reason());
            statement.setString(6, assessment.evidenceSource());
            statement.setTimestamp(7, Timestamp.from(assessment.evaluatedAt()));
            statement.setTimestamp(8, Timestamp.from(ingestedAt));
            statement.setString(9, evidenceSha256);
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
                throw new SQLException("Catalog state is missing for applicability import tenant");
            }
        }
    }

    private static String evidenceSha256(ApplicabilityCsvAssessment assessment) {
        String canonical = assessment.findingId() + "\u001F"
                + assessment.status().name() + "\u001F"
                + assessment.reason() + "\u001F"
                + assessment.evidenceSource() + "\u001F"
                + assessment.evaluatedAt();
        return sha256(canonical);
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(
                    digest.digest(value.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    /**
     * Derives a deterministic RFC 9562 version-8 UUID from the stored SHA-256 evidence digest.
     */
    private static UUID deterministicAssessmentId(String evidenceSha256) {
        byte[] bytes = HexFormat.of().parseHex(evidenceSha256.substring(0, 32));
        bytes[6] = (byte) ((bytes[6] & 0x0f) | 0x80);
        bytes[8] = (byte) ((bytes[8] & 0x3f) | 0x80);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        return new UUID(buffer.getLong(), buffer.getLong());
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
