package io.rbvm.postgres;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Durable end-to-end synchronization lifecycle around V30 source admission.
 *
 * <p>A job starts before any network acquisition occurs, so acquisition/build
 * failures remain visible even when there is no V30 source run to reference.</p>
 */
public final class PostgresPublicIntelligenceSyncJobStore implements PublicIntelligenceStatusReader {
    private static final int REQUIRED_SCHEMA_VERSION = 31;
    private static final Pattern SHA256 = Pattern.compile("^[a-f0-9]{64}$");

    public enum TriggerSource {
        MANUAL,
        SCHEDULED,
        STARTUP,
        SYSTEM
    }

    public enum Stage {
        ACQUIRING,
        BUILDING,
        ADMITTING,
        COMPLETE,
        FAILED
    }

    public enum Status {
        RUNNING,
        COMPLETE,
        FAILED
    }

    public record SourceIdentity(String sourceUri, String sourceVersion, String sourceSha256) {
        public SourceIdentity {
            sourceUri = requireText(sourceUri, "sourceUri");
            sourceVersion = requireText(sourceVersion, "sourceVersion");
            sourceSha256 = requireText(sourceSha256, "sourceSha256").toLowerCase();
            if (!sourceUri.startsWith("https://")) {
                throw new IllegalArgumentException("sourceUri must use https");
            }
            if (!SHA256.matcher(sourceSha256).matches()) {
                throw new IllegalArgumentException("sourceSha256 must be lowercase SHA-256");
            }
        }
    }

    public record Job(
            UUID id,
            PostgresPublicIntelligenceStore.Provider provider,
            TriggerSource triggerSource,
            Status status,
            Stage stage,
            Instant startedAt,
            Instant updatedAt,
            Instant completedAt,
            SourceIdentity source,
            UUID syncRunId,
            String errorCode,
            String errorDetail
    ) {
    }

    private final JdbcConnectionFactory connections;
    private final int schemaVersion;

    public PostgresPublicIntelligenceSyncJobStore(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        PostgresMigrator migrator = new PostgresMigrator(connections);
        schemaVersion = migrate ? migrator.migrate() : migrator.installedVersion();
        if (schemaVersion < REQUIRED_SCHEMA_VERSION) {
            throw new IOException(
                    "PostgreSQL schema version " + schemaVersion
                            + " is older than required version " + REQUIRED_SCHEMA_VERSION);
        }
    }

    public int schemaVersion() {
        return schemaVersion;
    }

    public Job start(
            PostgresPublicIntelligenceStore.Provider provider,
            TriggerSource triggerSource,
            Instant startedAt
    ) throws IOException {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(triggerSource, "triggerSource");
        Objects.requireNonNull(startedAt, "startedAt");
        UUID id = UUID.randomUUID();
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     INSERT INTO rbvm.public_intelligence_sync_job(
                         id, provider, trigger_source, status, stage, started_at, updated_at
                     ) VALUES (?, ?, ?, 'RUNNING', 'ACQUIRING', ?, ?)
                     """)) {
            statement.setObject(1, id);
            statement.setString(2, provider.name());
            statement.setString(3, triggerSource.name());
            statement.setTimestamp(4, Timestamp.from(startedAt));
            statement.setTimestamp(5, Timestamp.from(startedAt));
            statement.executeUpdate();
            return new Job(
                    id, provider, triggerSource, Status.RUNNING, Stage.ACQUIRING,
                    startedAt, startedAt, null, null, null, null, null);
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("PostgreSQL public-intelligence sync job start failed", exception);
        }
    }

    public Job acquired(
            UUID jobId,
            PostgresPublicIntelligenceStore.Provider provider,
            SourceIdentity source,
            Instant updatedAt
    ) throws IOException {
        Objects.requireNonNull(source, "source");
        return transition(
                jobId, provider, Stage.ACQUIRING, Stage.BUILDING, updatedAt,
                "source_uri = ?, source_version = ?, source_sha256 = ?,",
                statement -> {
                    statement.setString(1, source.sourceUri());
                    statement.setString(2, source.sourceVersion());
                    statement.setString(3, source.sourceSha256());
                    return 4;
                }
        );
    }

    public Job bundleBuilt(
            UUID jobId,
            PostgresPublicIntelligenceStore.Provider provider,
            Instant updatedAt
    ) throws IOException {
        return transition(
                jobId, provider, Stage.BUILDING, Stage.ADMITTING, updatedAt,
                "",
                statement -> 1
        );
    }

    public Job linkSyncRun(
            UUID jobId,
            PostgresPublicIntelligenceStore.Provider provider,
            UUID syncRunId,
            Instant updatedAt
    ) throws IOException {
        Objects.requireNonNull(jobId, "jobId");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(syncRunId, "syncRunId");
        Objects.requireNonNull(updatedAt, "updatedAt");
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     UPDATE rbvm.public_intelligence_sync_job
                     SET sync_run_id = ?, updated_at = ?
                     WHERE id = ? AND provider = ? AND status = 'RUNNING'
                       AND stage = 'ADMITTING' AND sync_run_id IS NULL
                     """)) {
            statement.setObject(1, syncRunId);
            statement.setTimestamp(2, Timestamp.from(updatedAt));
            statement.setObject(3, jobId);
            statement.setString(4, provider.name());
            if (statement.executeUpdate() != 1) {
                throw new IOException("public-intelligence sync job is not linkable in ADMITTING stage");
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("PostgreSQL public-intelligence sync-run link failed", exception);
        }
        return requireJob(jobId, provider);
    }

    public Job complete(
            UUID jobId,
            PostgresPublicIntelligenceStore.Provider provider,
            Instant completedAt
    ) throws IOException {
        Objects.requireNonNull(jobId, "jobId");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(completedAt, "completedAt");
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     UPDATE rbvm.public_intelligence_sync_job j
                     SET status = 'COMPLETE', stage = 'COMPLETE',
                         updated_at = ?, completed_at = ?
                     WHERE j.id = ? AND j.provider = ? AND j.status = 'RUNNING'
                       AND j.stage = 'ADMITTING' AND j.sync_run_id IS NOT NULL
                       AND EXISTS (
                           SELECT 1
                           FROM rbvm.public_intelligence_sync_run r
                           WHERE r.id = j.sync_run_id
                             AND r.provider = j.provider
                             AND r.status = 'COMPLETE'
                       )
                     """)) {
            statement.setTimestamp(1, Timestamp.from(completedAt));
            statement.setTimestamp(2, Timestamp.from(completedAt));
            statement.setObject(3, jobId);
            statement.setString(4, provider.name());
            if (statement.executeUpdate() != 1) {
                throw new IOException(
                        "public-intelligence sync job cannot complete before its linked V30 run is COMPLETE");
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("PostgreSQL public-intelligence sync job completion failed", exception);
        }
        return requireJob(jobId, provider);
    }

    public Job fail(
            UUID jobId,
            PostgresPublicIntelligenceStore.Provider provider,
            String errorCode,
            String errorDetail,
            Instant completedAt
    ) throws IOException {
        Objects.requireNonNull(jobId, "jobId");
        Objects.requireNonNull(provider, "provider");
        errorCode = requireText(errorCode, "errorCode");
        errorDetail = requireText(errorDetail, "errorDetail");
        Objects.requireNonNull(completedAt, "completedAt");
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     UPDATE rbvm.public_intelligence_sync_job
                     SET status = 'FAILED', stage = 'FAILED', updated_at = ?, completed_at = ?,
                         error_code = ?, error_detail = ?
                     WHERE id = ? AND provider = ? AND status = 'RUNNING'
                     """)) {
            statement.setTimestamp(1, Timestamp.from(completedAt));
            statement.setTimestamp(2, Timestamp.from(completedAt));
            statement.setString(3, errorCode);
            statement.setString(4, errorDetail);
            statement.setObject(5, jobId);
            statement.setString(6, provider.name());
            if (statement.executeUpdate() != 1) {
                throw new IOException("public-intelligence sync job is already terminal or does not exist");
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("PostgreSQL public-intelligence sync job failure transition failed", exception);
        }
        return requireJob(jobId, provider);
    }

    public Job requireJob(UUID jobId, PostgresPublicIntelligenceStore.Provider provider)
            throws IOException {
        Objects.requireNonNull(jobId, "jobId");
        Objects.requireNonNull(provider, "provider");
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT id, provider, trigger_source, status, stage,
                            started_at, updated_at, completed_at,
                            source_uri, source_version, source_sha256,
                            sync_run_id, error_code, error_detail
                     FROM rbvm.public_intelligence_sync_job
                     WHERE id = ? AND provider = ?
                     """)) {
            statement.setObject(1, jobId);
            statement.setString(2, provider.name());
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) throw new IOException("public-intelligence sync job does not exist");
                return job(rows);
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("PostgreSQL public-intelligence sync job read failed", exception);
        }
    }

    @Override
    public List<ProviderStatus> readStatus() throws IOException {
        List<ProviderStatus> result = new ArrayList<>();
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT provider,
                            latest_job_id, latest_job_trigger_source, latest_job_status,
                            latest_job_stage, latest_job_started_at, latest_job_updated_at,
                            latest_job_completed_at, latest_job_source_uri,
                            latest_job_source_version, latest_job_source_sha256,
                            latest_job_sync_run_id, latest_job_error_code, latest_job_error_detail,
                            latest_success_id, latest_success_mode, latest_success_source_uri,
                            latest_success_source_version, latest_success_source_sha256,
                            latest_success_source_published_at, latest_success_observed_at,
                            latest_success_completed_at, latest_success_record_count
                     FROM rbvm.public_intelligence_provider_status_v1
                     ORDER BY provider
                     """)) {
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    result.add(new ProviderStatus(
                            PostgresPublicIntelligenceStore.Provider.valueOf(rows.getString(1)),
                            rows.getObject(2, UUID.class),
                            rows.getString(3),
                            rows.getString(4),
                            rows.getString(5),
                            instant(rows, 6),
                            instant(rows, 7),
                            instant(rows, 8),
                            rows.getString(9),
                            rows.getString(10),
                            trim(rows.getString(11)),
                            rows.getObject(12, UUID.class),
                            rows.getString(13),
                            rows.getString(14),
                            rows.getObject(15, UUID.class),
                            rows.getString(16),
                            rows.getString(17),
                            rows.getString(18),
                            trim(rows.getString(19)),
                            instant(rows, 20),
                            instant(rows, 21),
                            instant(rows, 22),
                            nullableLong(rows, 23)
                    ));
                }
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("PostgreSQL public-intelligence provider status read failed", exception);
        }
        return List.copyOf(result);
    }

    private Job transition(
            UUID jobId,
            PostgresPublicIntelligenceStore.Provider provider,
            Stage expected,
            Stage next,
            Instant updatedAt,
            String prefixAssignments,
            Binder binder
    ) throws IOException {
        Objects.requireNonNull(jobId, "jobId");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(expected, "expected");
        Objects.requireNonNull(next, "next");
        Objects.requireNonNull(updatedAt, "updatedAt");
        String sql = "UPDATE rbvm.public_intelligence_sync_job SET "
                + prefixAssignments
                + " stage = ?, updated_at = ? WHERE id = ? AND provider = ? "
                + "AND status = 'RUNNING' AND stage = ?";
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            int index = binder.bind(statement);
            statement.setString(index++, next.name());
            statement.setTimestamp(index++, Timestamp.from(updatedAt));
            statement.setObject(index++, jobId);
            statement.setString(index++, provider.name());
            statement.setString(index, expected.name());
            if (statement.executeUpdate() != 1) {
                throw new IOException(
                        "public-intelligence sync job is not in expected stage " + expected.name());
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("PostgreSQL public-intelligence sync job transition failed", exception);
        }
        return requireJob(jobId, provider);
    }

    private static Job job(ResultSet rows) throws SQLException {
        String sourceUri = rows.getString(9);
        SourceIdentity source = sourceUri == null ? null : new SourceIdentity(
                sourceUri, rows.getString(10), trim(rows.getString(11)));
        return new Job(
                rows.getObject(1, UUID.class),
                PostgresPublicIntelligenceStore.Provider.valueOf(rows.getString(2)),
                TriggerSource.valueOf(rows.getString(3)),
                Status.valueOf(rows.getString(4)),
                Stage.valueOf(rows.getString(5)),
                instant(rows, 6),
                instant(rows, 7),
                instant(rows, 8),
                source,
                rows.getObject(12, UUID.class),
                rows.getString(13),
                rows.getString(14)
        );
    }

    private static Instant instant(ResultSet rows, int column) throws SQLException {
        Timestamp value = rows.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }

    private static Long nullableLong(ResultSet rows, int column) throws SQLException {
        long value = rows.getLong(column);
        return rows.wasNull() ? null : value;
    }

    private static String trim(String value) {
        return value == null ? null : value.trim();
    }

    private static String requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        String normalized = value.trim();
        if (normalized.isEmpty()) throw new IllegalArgumentException(field + " must not be blank");
        return normalized;
    }

    @FunctionalInterface
    private interface Binder {
        int bind(PreparedStatement statement) throws SQLException;
    }
}
