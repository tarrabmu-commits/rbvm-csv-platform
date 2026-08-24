package io.rbvm.postgres;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Global, non-tenant persistence boundary for the operational public-intelligence mirror.
 *
 * <p>This store deliberately does not materialize tenant evidence, priority, risk, SLA,
 * customer context, or applicability. Provider records become readable only after their
 * exact source run reaches COMPLETE. Historical rows are append-only and a TOMBSTONE in a
 * newer complete run suppresses an older provider record without deleting history.</p>
 */
public final class PostgresPublicIntelligenceStore {
    private static final int REQUIRED_SCHEMA_VERSION = 30;
    private static final long SYNC_LOCK_BASE = 7_641_039_205_114_200_000L;
    private static final Pattern CVE_PATTERN = Pattern.compile("^CVE-[0-9]{4}-[0-9]{4,}$");
    private static final Pattern SHA256_PATTERN = Pattern.compile("^[a-f0-9]{64}$");

    public enum Provider {
        NVD,
        FIRST_EPSS,
        CISA_KEV,
        CVE_PROGRAM
    }

    public enum SyncMode {
        BOOTSTRAP,
        INCREMENTAL
    }

    public enum SyncStatus {
        STAGING,
        COMPLETE,
        FAILED
    }

    public enum RecordState {
        ACTIVE,
        TOMBSTONE
    }

    public record SourceDescriptor(
            Provider provider,
            String sourceUri,
            String sourceVersion,
            String sourceSha256,
            Instant sourcePublishedAt,
            Instant observedAt
    ) {
        public SourceDescriptor {
            provider = Objects.requireNonNull(provider, "provider");
            sourceUri = requireText(sourceUri, "sourceUri");
            if (!sourceUri.startsWith("https://")) {
                throw new IllegalArgumentException("sourceUri must use https");
            }
            sourceVersion = requireText(sourceVersion, "sourceVersion");
            sourceSha256 = requireSha256(sourceSha256, "sourceSha256");
            observedAt = Objects.requireNonNull(observedAt, "observedAt");
            if (sourcePublishedAt != null && sourcePublishedAt.isAfter(observedAt)) {
                throw new IllegalArgumentException("sourcePublishedAt must not be after observedAt");
            }
        }
    }

    public record RecordVersion(
            String cveId,
            RecordState state,
            Instant sourceModifiedAt,
            Instant sourcePublishedAt,
            String payloadJson,
            Instant observedAt
    ) {
        public RecordVersion {
            cveId = requireCve(cveId);
            state = Objects.requireNonNull(state, "state");
            observedAt = Objects.requireNonNull(observedAt, "observedAt");
            if (sourcePublishedAt != null && sourceModifiedAt != null
                    && sourcePublishedAt.isAfter(sourceModifiedAt)) {
                throw new IllegalArgumentException(
                        "sourcePublishedAt must not be after sourceModifiedAt");
            }
            if (state == RecordState.ACTIVE) {
                payloadJson = requireText(payloadJson, "payloadJson");
            } else if (payloadJson != null) {
                throw new IllegalArgumentException("TOMBSTONE must not carry payloadJson");
            }
        }

        public String recordSha256() {
            String canonical = cveId + '\u001f'
                    + state.name() + '\u001f'
                    + nullableInstant(sourceModifiedAt) + '\u001f'
                    + nullableInstant(sourcePublishedAt) + '\u001f'
                    + (payloadJson == null ? "" : payloadJson) + '\u001f'
                    + observedAt;
            return sha256(canonical);
        }
    }

    public record BeginResult(UUID runId, boolean replayed, SyncStatus status) {
        public BeginResult {
            Objects.requireNonNull(runId, "runId");
            Objects.requireNonNull(status, "status");
        }
    }

    public record AppendResult(long insertedRecords, long replayedRecords) {
        public AppendResult {
            if (insertedRecords < 0 || replayedRecords < 0) {
                throw new IllegalArgumentException("record counts must be non-negative");
            }
        }
    }

    public record CompletionResult(boolean replayed, long recordCount) {
        public CompletionResult {
            if (recordCount < 0) throw new IllegalArgumentException("recordCount must be non-negative");
        }
    }

    public record FailureResult(boolean replayed, long recordCount) {
        public FailureResult {
            if (recordCount < 0) throw new IllegalArgumentException("recordCount must be non-negative");
        }
    }

    public record CurrentRecord(
            Provider provider,
            String cveId,
            String payloadJson,
            String recordSha256,
            Instant sourceModifiedAt,
            Instant sourcePublishedAt,
            Instant recordObservedAt,
            UUID syncRunId,
            SyncMode syncMode,
            String sourceUri,
            String sourceVersion,
            String sourceSha256,
            Instant runObservedAt,
            Instant runCompletedAt
    ) {
        public CurrentRecord {
            Objects.requireNonNull(provider, "provider");
            cveId = requireCve(cveId);
            payloadJson = requireText(payloadJson, "payloadJson");
            recordSha256 = requireSha256(recordSha256, "recordSha256");
            Objects.requireNonNull(recordObservedAt, "recordObservedAt");
            Objects.requireNonNull(syncRunId, "syncRunId");
            Objects.requireNonNull(syncMode, "syncMode");
            sourceUri = requireText(sourceUri, "sourceUri");
            sourceVersion = requireText(sourceVersion, "sourceVersion");
            sourceSha256 = requireSha256(sourceSha256, "sourceSha256");
            Objects.requireNonNull(runObservedAt, "runObservedAt");
            Objects.requireNonNull(runCompletedAt, "runCompletedAt");
        }
    }

    public static final class ConflictException extends IOException {
        private static final long serialVersionUID = 1L;

        ConflictException(String message) {
            super(message);
        }
    }

    private final JdbcConnectionFactory connections;
    private final int schemaVersion;

    public PostgresPublicIntelligenceStore(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        PostgresMigrator migrator = new PostgresMigrator(connections);
        this.schemaVersion = migrate ? migrator.migrate() : migrator.installedVersion();
        if (schemaVersion < REQUIRED_SCHEMA_VERSION) {
            throw new IOException(
                    "PostgreSQL schema version " + schemaVersion
                            + " is older than required version " + REQUIRED_SCHEMA_VERSION);
        }
    }

    public int schemaVersion() {
        return schemaVersion;
    }

    public BeginResult beginOrReplay(
            SourceDescriptor source,
            SyncMode mode,
            Instant startedAt
    ) throws IOException {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(startedAt, "startedAt");
        if (startedAt.isAfter(source.observedAt())) {
            throw new IllegalArgumentException("startedAt must not be after observedAt");
        }

        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                lockProvider(connection, source.provider());
                StoredRun existing = existingNonFailedSource(connection, source);
                if (existing != null) {
                    connection.commit();
                    return new BeginResult(existing.id(), true, existing.status());
                }

                UUID runId = UUID.randomUUID();
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO rbvm.public_intelligence_sync_run(
                            id, provider, sync_mode, status, source_uri, source_version,
                            source_sha256, source_published_at, observed_at, started_at
                        ) VALUES (?, ?, ?, 'STAGING', ?, ?, ?, ?, ?, ?)
                        """)) {
                    statement.setObject(1, runId);
                    statement.setString(2, source.provider().name());
                    statement.setString(3, mode.name());
                    statement.setString(4, source.sourceUri());
                    statement.setString(5, source.sourceVersion());
                    statement.setString(6, source.sourceSha256());
                    setInstant(statement, 7, source.sourcePublishedAt());
                    statement.setTimestamp(8, Timestamp.from(source.observedAt()));
                    statement.setTimestamp(9, Timestamp.from(startedAt));
                    statement.executeUpdate();
                }
                connection.commit();
                return new BeginResult(runId, false, SyncStatus.STAGING);
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL public-intelligence sync start failed", sqlException);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL public-intelligence sync transaction", exception);
        }
    }

    public AppendResult appendRecords(
            UUID runId,
            Provider provider,
            List<RecordVersion> records
    ) throws IOException {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(records, "records");

        Map<String, RecordVersion> unique = new LinkedHashMap<>();
        for (RecordVersion record : records) {
            Objects.requireNonNull(record, "record");
            RecordVersion previous = unique.putIfAbsent(record.cveId(), record);
            if (previous != null && !previous.equals(record)) {
                throw new ConflictException(
                        "one append batch contains different records for " + record.cveId());
            }
        }
        if (unique.isEmpty()) return new AppendResult(0, 0);

        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                requireRunForUpdate(connection, runId, provider, SyncStatus.STAGING);
                Map<String, String> existing = existingRecordHashes(
                        connection, runId, unique.keySet());
                List<RecordVersion> missing = new ArrayList<>();
                long replayed = 0;
                for (RecordVersion record : unique.values()) {
                    String storedHash = existing.get(record.cveId());
                    if (storedHash == null) {
                        missing.add(record);
                    } else if (storedHash.equals(record.recordSha256())) {
                        replayed++;
                    } else {
                        throw new ConflictException(
                                "sync run already contains different immutable content for "
                                        + record.cveId());
                    }
                }

                if (!missing.isEmpty()) {
                    try (PreparedStatement statement = connection.prepareStatement("""
                            INSERT INTO rbvm.public_intelligence_record(
                                sync_run_id, provider, cve_id, record_state,
                                source_modified_at, source_published_at, payload_json,
                                record_sha256, observed_at
                            ) VALUES (?, ?, ?, ?, ?, ?, CAST(? AS jsonb), ?, ?)
                            """)) {
                        for (RecordVersion record : missing) {
                            statement.setObject(1, runId);
                            statement.setString(2, provider.name());
                            statement.setString(3, record.cveId());
                            statement.setString(4, record.state().name());
                            setInstant(statement, 5, record.sourceModifiedAt());
                            setInstant(statement, 6, record.sourcePublishedAt());
                            if (record.payloadJson() == null) {
                                statement.setNull(7, Types.VARCHAR);
                            } else {
                                statement.setString(7, record.payloadJson());
                            }
                            statement.setString(8, record.recordSha256());
                            statement.setTimestamp(9, Timestamp.from(record.observedAt()));
                            statement.addBatch();
                        }
                        statement.executeBatch();
                    }
                }
                connection.commit();
                return new AppendResult(missing.size(), replayed);
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL public-intelligence record append failed", sqlException);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL public-intelligence append transaction", exception);
        }
    }

    public CompletionResult completeRun(
            UUID runId,
            Provider provider,
            long expectedRecordCount,
            Instant completedAt
    ) throws IOException {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(completedAt, "completedAt");
        if (expectedRecordCount < 0) {
            throw new IllegalArgumentException("expectedRecordCount must be non-negative");
        }

        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                StoredRun run = requireRunForUpdate(connection, runId, provider, null);
                long actual = recordCount(connection, runId);
                if (run.status() == SyncStatus.COMPLETE) {
                    if (run.recordCount() != null && run.recordCount() == expectedRecordCount
                            && actual == expectedRecordCount) {
                        connection.commit();
                        return new CompletionResult(true, actual);
                    }
                    throw new ConflictException("completed sync run record count does not match replay");
                }
                if (run.status() == SyncStatus.FAILED) {
                    throw new ConflictException("failed sync run cannot be completed");
                }
                if (actual != expectedRecordCount) {
                    throw new ConflictException(
                            "sync run contains " + actual + " records but "
                                    + expectedRecordCount + " were expected");
                }

                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE rbvm.public_intelligence_sync_run
                        SET status = 'COMPLETE', completed_at = ?, record_count = ?
                        WHERE id = ? AND provider = ? AND status = 'STAGING'
                        """)) {
                    statement.setTimestamp(1, Timestamp.from(completedAt));
                    statement.setLong(2, actual);
                    statement.setObject(3, runId);
                    statement.setString(4, provider.name());
                    if (statement.executeUpdate() != 1) {
                        throw new SQLException("public-intelligence sync run changed concurrently");
                    }
                }
                connection.commit();
                return new CompletionResult(false, actual);
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL public-intelligence completion failed", sqlException);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL public-intelligence completion transaction", exception);
        }
    }

    public FailureResult failRun(
            UUID runId,
            Provider provider,
            String errorCode,
            String errorDetail,
            Instant completedAt
    ) throws IOException {
        Objects.requireNonNull(runId, "runId");
        Objects.requireNonNull(provider, "provider");
        errorCode = requireText(errorCode, "errorCode");
        errorDetail = requireText(errorDetail, "errorDetail");
        Objects.requireNonNull(completedAt, "completedAt");

        try (Connection connection = connections.open()) {
            beginTransaction(connection);
            try {
                StoredRun run = requireRunForUpdate(connection, runId, provider, null);
                long actual = recordCount(connection, runId);
                if (run.status() == SyncStatus.FAILED) {
                    connection.commit();
                    return new FailureResult(true, actual);
                }
                if (run.status() == SyncStatus.COMPLETE) {
                    throw new ConflictException("completed sync run cannot be failed");
                }

                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE rbvm.public_intelligence_sync_run
                        SET status = 'FAILED', completed_at = ?, record_count = ?,
                            error_code = ?, error_detail = ?
                        WHERE id = ? AND provider = ? AND status = 'STAGING'
                        """)) {
                    statement.setTimestamp(1, Timestamp.from(completedAt));
                    statement.setLong(2, actual);
                    statement.setString(3, errorCode);
                    statement.setString(4, errorDetail);
                    statement.setObject(5, runId);
                    statement.setString(6, provider.name());
                    if (statement.executeUpdate() != 1) {
                        throw new SQLException("public-intelligence sync run changed concurrently");
                    }
                }
                connection.commit();
                return new FailureResult(false, actual);
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL public-intelligence failure transition failed", sqlException);
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL public-intelligence failure transaction", exception);
        }
    }

    public Map<String, Map<Provider, CurrentRecord>> lookupCurrent(Set<String> requestedCves)
            throws IOException {
        Objects.requireNonNull(requestedCves, "requestedCves");
        Set<String> cves = new LinkedHashSet<>();
        for (String cve : requestedCves) cves.add(requireCve(cve));
        if (cves.isEmpty()) return Map.of();

        String sql = """
                SELECT provider, cve_id, payload_json::text, record_sha256,
                       source_modified_at, source_published_at, record_observed_at,
                       sync_run_id, sync_mode, source_uri, source_version, source_sha256,
                       run_observed_at, run_completed_at
                FROM rbvm.current_public_intelligence_record
                WHERE cve_id = ANY (?)
                ORDER BY cve_id, provider
                """;
        Map<String, Map<Provider, CurrentRecord>> result = new LinkedHashMap<>();
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            Array array = connection.createArrayOf("text", cves.toArray(String[]::new));
            try {
                statement.setArray(1, array);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        Provider provider = Provider.valueOf(rows.getString(1));
                        String cve = rows.getString(2);
                        CurrentRecord record = new CurrentRecord(
                                provider,
                                cve,
                                rows.getString(3),
                                rows.getString(4).trim(),
                                instant(rows, 5),
                                instant(rows, 6),
                                instant(rows, 7),
                                rows.getObject(8, UUID.class),
                                SyncMode.valueOf(rows.getString(9)),
                                rows.getString(10),
                                rows.getString(11),
                                rows.getString(12).trim(),
                                instant(rows, 13),
                                instant(rows, 14)
                        );
                        result.computeIfAbsent(cve, ignored -> new EnumMap<>(Provider.class))
                                .put(provider, record);
                    }
                }
            } finally {
                array.free();
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "PostgreSQL public-intelligence local lookup failed", exception);
        }

        Map<String, Map<Provider, CurrentRecord>> immutable = new LinkedHashMap<>();
        for (Map.Entry<String, Map<Provider, CurrentRecord>> entry : result.entrySet()) {
            immutable.put(entry.getKey(), Collections.unmodifiableMap(entry.getValue()));
        }
        return Collections.unmodifiableMap(immutable);
    }

    private static StoredRun existingNonFailedSource(
            Connection connection,
            SourceDescriptor source
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, status, record_count
                FROM rbvm.public_intelligence_sync_run
                WHERE provider = ? AND source_sha256 = ?
                  AND status IN ('STAGING', 'COMPLETE')
                ORDER BY started_at DESC, id DESC
                LIMIT 1
                """)) {
            statement.setString(1, source.provider().name());
            statement.setString(2, source.sourceSha256());
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) return null;
                return new StoredRun(
                        rows.getObject(1, UUID.class),
                        source.provider(),
                        SyncStatus.valueOf(rows.getString(2)),
                        nullableLong(rows, 3)
                );
            }
        }
    }

    private static StoredRun requireRunForUpdate(
            Connection connection,
            UUID runId,
            Provider provider,
            SyncStatus requiredStatus
    ) throws SQLException, ConflictException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT provider, status, record_count
                FROM rbvm.public_intelligence_sync_run
                WHERE id = ?
                FOR UPDATE
                """)) {
            statement.setObject(1, runId);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) throw new ConflictException("public-intelligence sync run does not exist");
                Provider storedProvider = Provider.valueOf(rows.getString(1));
                SyncStatus status = SyncStatus.valueOf(rows.getString(2));
                if (storedProvider != provider) {
                    throw new ConflictException("sync run provider does not match requested provider");
                }
                if (requiredStatus != null && status != requiredStatus) {
                    throw new ConflictException(
                            "sync run is " + status + " but " + requiredStatus + " is required");
                }
                return new StoredRun(runId, storedProvider, status, nullableLong(rows, 3));
            }
        }
    }

    private static Map<String, String> existingRecordHashes(
            Connection connection,
            UUID runId,
            Set<String> cves
    ) throws SQLException {
        Map<String, String> result = new LinkedHashMap<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT cve_id, record_sha256
                FROM rbvm.public_intelligence_record
                WHERE sync_run_id = ? AND cve_id = ANY (?)
                """)) {
            statement.setObject(1, runId);
            Array array = connection.createArrayOf("text", cves.toArray(String[]::new));
            try {
                statement.setArray(2, array);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) result.put(rows.getString(1), rows.getString(2).trim());
                }
            } finally {
                array.free();
            }
        }
        return result;
    }

    private static long recordCount(Connection connection, UUID runId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT count(*) FROM rbvm.public_intelligence_record WHERE sync_run_id = ?")) {
            statement.setObject(1, runId);
            try (ResultSet rows = statement.executeQuery()) {
                rows.next();
                return rows.getLong(1);
            }
        }
    }

    private static void beginTransaction(Connection connection) throws SQLException {
        connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
        connection.setAutoCommit(false);
    }

    private static void lockProvider(Connection connection, Provider provider) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pg_advisory_xact_lock(?)")) {
            statement.setLong(1, SYNC_LOCK_BASE + provider.ordinal());
            statement.execute();
        }
    }

    private static void rollback(Connection connection, Exception cause) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            cause.addSuppressed(rollbackFailure);
        }
    }

    private static void setInstant(PreparedStatement statement, int index, Instant value)
            throws SQLException {
        if (value == null) statement.setNull(index, Types.TIMESTAMP_WITH_TIMEZONE);
        else statement.setTimestamp(index, Timestamp.from(value));
    }

    private static Instant instant(ResultSet rows, int index) throws SQLException {
        Timestamp value = rows.getTimestamp(index);
        return value == null ? null : value.toInstant();
    }

    private static Long nullableLong(ResultSet rows, int index) throws SQLException {
        long value = rows.getLong(index);
        return rows.wasNull() ? null : value;
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
        return value.trim();
    }

    private static String requireCve(String value) {
        String normalized = requireText(value, "cveId").toUpperCase(Locale.ROOT);
        if (!CVE_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException("invalid CVE identifier: " + value);
        }
        return normalized;
    }

    private static String requireSha256(String value, String label) {
        String normalized = requireText(value, label).toLowerCase(Locale.ROOT);
        if (!SHA256_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException(label + " must be lowercase SHA-256");
        }
        return normalized;
    }

    private static String nullableInstant(Instant value) {
        return value == null ? "" : value.toString();
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    private record StoredRun(
            UUID id,
            Provider provider,
            SyncStatus status,
            Long recordCount
    ) {
    }
}
