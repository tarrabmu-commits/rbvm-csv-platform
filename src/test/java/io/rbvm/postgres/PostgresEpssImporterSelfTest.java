package io.rbvm.postgres;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public final class PostgresEpssImporterSelfTest {
    private static final Instant NOW = Instant.parse("2026-08-19T12:30:00Z");
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID VULN_A = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static final UUID VULN_B = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private static final String CVE_A = "CVE-2026-10001";
    private static final String CVE_B = "CVE-2026-10002";
    private static final String FOREIGN_CVE = "CVE-2026-19999";
    private static final String SOURCE =
            "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
    private static final String SHA_A = "a".repeat(64);
    private static final String SHA_B = "b".repeat(64);
    private static final String SHA_C = "c".repeat(64);

    private PostgresEpssImporterSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        importsSnapshotBoundScoresAndQuarantinesConflictsWithoutChoosingWinners();
        System.out.println("PostgresEpssImporterSelfTest: PASS");
    }

    private static void importsSnapshotBoundScoresAndQuarantinesConflictsWithoutChoosingWinners()
            throws Exception {
        Path first = Files.createTempFile("epss-import-", ".csv");
        Path persistedSnapshotConflict = Files.createTempFile("epss-snapshot-conflict-", ".csv");
        Path fileSnapshotConflict = Files.createTempFile("epss-file-conflict-", ".csv");
        try {
            Files.writeString(first, headers()
                    + row(CVE_A, "0.125", "0.875", "2025.03.14", "2026-08-19",
                            "2026-08-19T09:00:00Z", SHA_A)
                    + row(CVE_A, "0.1250", "0.8750", "2025.03.14", "2026-08-19",
                            "2026-08-19T09:00:00Z", SHA_A)
                    + row(CVE_B, "0.5001", "0.9500", "2025.03.14", "2026-08-19",
                            "2026-08-19T09:00:00Z", SHA_A)
                    + row(FOREIGN_CVE, "0.2", "0.8", "2025.03.14", "2026-08-19",
                            "2026-08-19T09:00:00Z", SHA_A),
                    StandardCharsets.UTF_8);

            Files.writeString(persistedSnapshotConflict, headers()
                    + row(CVE_A, "0.2", "0.9", "2025.03.15", "2026-08-18",
                            "2026-08-19T09:00:00Z", SHA_B),
                    StandardCharsets.UTF_8);

            // Same source and observation time but contradictory model/date/source bytes across CVEs.
            // The importer must quarantine the whole group instead of making row order a policy.
            Files.writeString(fileSnapshotConflict, headers()
                    + row(CVE_A, "0.3", "0.91", "2025.03.14", "2026-08-20",
                            "2026-08-19T11:00:00Z", SHA_B)
                    + row(CVE_B, "0.4", "0.92", "2025.03.15", "2026-08-20",
                            "2026-08-19T11:00:00Z", SHA_C),
                    StandardCharsets.UTF_8);

            FakeDatabase database = new FakeDatabase();
            database.vulnerabilities.put(CVE_A, VULN_A);
            database.vulnerabilities.put(CVE_B, VULN_B);
            PostgresEpssImporter importer = new PostgresEpssImporter(
                    database::connection,
                    false,
                    Clock.fixed(NOW, ZoneOffset.UTC)
            );

            EpssImportResult firstResult = importer.importFile(first);
            assert importer.schemaVersion() == 12;
            assert firstResult.analysis().logicalRows() == 4;
            assert firstResult.analysis().deduplicatedRows() == 1;
            assert firstResult.analysis().acceptedRows() == 3;
            assert firstResult.insertedSnapshots() == 1;
            assert firstResult.replayedSnapshots() == 0;
            assert firstResult.snapshotConflictGroups() == 0;
            assert firstResult.insertedEvidence() == 2;
            assert firstResult.replayedEvidence() == 0;
            assert firstResult.persistenceQuarantinedRows() == 1;
            assert firstResult.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals("CVE_NOT_FOUND_IN_TENANT"));
            assert database.snapshots.size() == 1;
            assert database.evidence.size() == 2;
            assert database.catalogRevision == 1;

            StoredSnapshot snapshot = database.snapshots.values().iterator().next();
            assert snapshot.modelVersion.equals("2025.03.14");
            assert snapshot.scoreDate.equals(LocalDate.parse("2026-08-19"));
            assert snapshot.sourceSha256.equals(SHA_A);
            StoredEvidence evidenceA = database.evidence.get(evidenceKey(VULN_A, snapshot.id));
            assert evidenceA.probability.compareTo(new BigDecimal("0.125")) == 0;
            assert evidenceA.percentile.compareTo(new BigDecimal("0.875")) == 0;

            EpssImportResult replay = importer.importFile(first);
            assert replay.insertedSnapshots() == 0;
            assert replay.replayedSnapshots() == 1;
            assert replay.insertedEvidence() == 0;
            assert replay.replayedEvidence() == 2;
            assert replay.persistenceQuarantinedRows() == 1;
            assert database.catalogRevision == 1 : "pure replay must not change catalog revision";

            EpssImportResult persistedConflict = importer.importFile(persistedSnapshotConflict);
            assert persistedConflict.insertedSnapshots() == 0;
            assert persistedConflict.replayedSnapshots() == 0;
            assert persistedConflict.snapshotConflictGroups() == 1;
            assert persistedConflict.insertedEvidence() == 0;
            assert persistedConflict.persistenceQuarantinedRows() == 1;
            assert persistedConflict.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals(
                            "CONFLICTING_PERSISTED_EPSS_SNAPSHOT_TIMESTAMP"));
            assert database.snapshots.size() == 1;
            assert database.evidence.size() == 2;
            assert database.catalogRevision == 1;

            EpssImportResult fileConflict = importer.importFile(fileSnapshotConflict);
            assert fileConflict.insertedSnapshots() == 0;
            assert fileConflict.replayedSnapshots() == 0;
            assert fileConflict.snapshotConflictGroups() == 1;
            assert fileConflict.insertedEvidence() == 0;
            assert fileConflict.replayedEvidence() == 0;
            assert fileConflict.persistenceQuarantinedRows() == 2;
            assert fileConflict.persistenceIssues().stream()
                    .filter(issue -> issue.code().equals("CONFLICTING_EPSS_SNAPSHOT_TIMESTAMP"))
                    .count() == 2;
            assert database.snapshots.size() == 1;
            assert database.catalogRevision == 1;

            // Persisted CVE score conflict is quarantined rather than overwritten.
            String evidenceKey = database.evidence.keySet().stream()
                    .filter(key -> key.startsWith(VULN_A.toString()))
                    .findFirst().orElseThrow();
            StoredEvidence original = database.evidence.get(evidenceKey);
            database.evidence.put(evidenceKey, original.withSha("f".repeat(64)));
            EpssImportResult evidenceConflict = importer.importFile(first);
            assert evidenceConflict.replayedSnapshots() == 1;
            assert evidenceConflict.insertedEvidence() == 0;
            assert evidenceConflict.replayedEvidence() == 1;
            assert evidenceConflict.persistenceQuarantinedRows() == 2;
            assert evidenceConflict.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals(
                            "CONFLICTING_PERSISTED_EPSS_EVIDENCE"));
            assert database.catalogRevision == 1;

            assert database.commits == 5;
            assert database.rollbacks == 0;
            assert database.serializableTransactions == 5;
        } finally {
            Files.deleteIfExists(first);
            Files.deleteIfExists(persistedSnapshotConflict);
            Files.deleteIfExists(fileSnapshotConflict);
        }
    }

    private static String headers() {
        return "CVE_ID,EPSS_Probability,EPSS_Percentile,EPSS_Model_Version,EPSS_Score_Date,"
                + "EPSS_Source,EPSS_Observed_At,EPSS_Source_SHA256\r\n";
    }

    private static String row(
            String cve,
            String probability,
            String percentile,
            String modelVersion,
            String scoreDate,
            String observedAt,
            String sha
    ) {
        return cve + "," + probability + "," + percentile + "," + modelVersion + ","
                + scoreDate + "," + SOURCE + "," + observedAt + "," + sha + "\r\n";
    }

    private static final class FakeDatabase {
        private final Map<String, UUID> vulnerabilities = new HashMap<>();
        private final Map<String, StoredSnapshot> snapshots = new HashMap<>();
        private final Map<String, StoredEvidence> evidence = new HashMap<>();
        private int commits;
        private int rollbacks;
        private int serializableTransactions;
        private long catalogRevision;

        private Connection connection() {
            return proxy(Connection.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "createStatement" -> statement();
                case "prepareStatement" -> prepared((String) arguments[0]);
                case "setTransactionIsolation" -> {
                    if ((Integer) arguments[0] == Connection.TRANSACTION_SERIALIZABLE) {
                        serializableTransactions++;
                    }
                    yield null;
                }
                case "setAutoCommit", "close" -> null;
                case "commit" -> {
                    commits++;
                    yield null;
                }
                case "rollback" -> {
                    rollbacks++;
                    yield null;
                }
                case "getAutoCommit" -> true;
                case "isClosed" -> false;
                default -> defaultValue(method.getReturnType());
            });
        }

        private Statement statement() {
            return proxy(Statement.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "executeQuery" -> rows(new Object[]{12});
                case "close" -> null;
                default -> defaultValue(method.getReturnType());
            });
        }

        private PreparedStatement prepared(String sql) {
            Map<Integer, Object> parameters = new HashMap<>();
            return proxy(PreparedStatement.class, (proxy, method, arguments) -> {
                String name = method.getName();
                if (name.startsWith("set") && arguments != null && arguments.length >= 2
                        && arguments[0] instanceof Integer index) {
                    parameters.put(index, arguments[1]);
                    return null;
                }
                return switch (name) {
                    case "execute" -> false;
                    case "executeQuery" -> query(sql, parameters);
                    case "executeUpdate" -> update(sql, parameters);
                    case "close" -> null;
                    default -> defaultValue(method.getReturnType());
                };
            });
        }

        private ResultSet query(String sql, Map<Integer, Object> parameters) {
            if (sql.contains("SELECT id FROM rbvm.tenant")) {
                return rows(new Object[]{TENANT_ID});
            }
            if (sql.contains("JOIN rbvm.exposure")) {
                UUID tenant = (UUID) parameters.get(1);
                String cve = (String) parameters.get(2);
                UUID vulnerability = tenant.equals(TENANT_ID) ? vulnerabilities.get(cve) : null;
                return vulnerability == null ? rows() : rows(new Object[]{vulnerability});
            }
            if (sql.contains("FROM rbvm.epss_score_snapshot")) {
                String source = (String) parameters.get(2);
                Instant observedAt = ((Timestamp) parameters.get(3)).toInstant();
                StoredSnapshot stored = snapshots.get(snapshotKey(source, observedAt));
                return stored == null ? rows() : rows(new Object[]{
                        stored.id,
                        stored.modelVersion,
                        Date.valueOf(stored.scoreDate),
                        stored.sourceSha256
                });
            }
            if (sql.contains("FROM rbvm.epss_evidence")) {
                UUID vulnerability = (UUID) parameters.get(2);
                UUID snapshotId = (UUID) parameters.get(3);
                StoredEvidence stored = evidence.get(evidenceKey(vulnerability, snapshotId));
                return stored == null ? rows() : rows(new Object[]{stored.sha256});
            }
            throw new AssertionError("Unexpected query:\n" + sql);
        }

        private int update(String sql, Map<Integer, Object> parameters) {
            if (sql.contains("INSERT INTO rbvm.epss_score_snapshot")) {
                UUID id = (UUID) parameters.get(1);
                String modelVersion = (String) parameters.get(3);
                LocalDate scoreDate = ((Date) parameters.get(4)).toLocalDate();
                String source = (String) parameters.get(5);
                String sourceSha = (String) parameters.get(6);
                Instant observedAt = ((Timestamp) parameters.get(7)).toInstant();
                String key = snapshotKey(source, observedAt);
                if (snapshots.putIfAbsent(
                        key,
                        new StoredSnapshot(id, modelVersion, scoreDate, source, sourceSha, observedAt)
                ) != null) {
                    throw new AssertionError("Importer attempted duplicate EPSS snapshot insert");
                }
                return 1;
            }
            if (sql.contains("INSERT INTO rbvm.epss_evidence")) {
                UUID vulnerability = (UUID) parameters.get(3);
                UUID snapshotId = (UUID) parameters.get(4);
                BigDecimal probability = (BigDecimal) parameters.get(5);
                BigDecimal percentile = (BigDecimal) parameters.get(6);
                String sha256 = (String) parameters.get(8);
                String key = evidenceKey(vulnerability, snapshotId);
                if (evidence.putIfAbsent(
                        key,
                        new StoredEvidence(probability, percentile, sha256)
                ) != null) {
                    throw new AssertionError("Importer attempted duplicate EPSS evidence insert");
                }
                return 1;
            }
            if (sql.contains("UPDATE rbvm.catalog_state")) {
                catalogRevision++;
                return 1;
            }
            throw new AssertionError("Unexpected update:\n" + sql);
        }
    }

    private record StoredSnapshot(
            UUID id,
            String modelVersion,
            LocalDate scoreDate,
            String source,
            String sourceSha256,
            Instant observedAt
    ) {
    }

    private record StoredEvidence(
            BigDecimal probability,
            BigDecimal percentile,
            String sha256
    ) {
        private StoredEvidence withSha(String replacement) {
            return new StoredEvidence(probability, percentile, replacement);
        }
    }

    private static String snapshotKey(String source, Instant observedAt) {
        return source + "|" + observedAt;
    }

    private static String evidenceKey(UUID vulnerability, UUID snapshotId) {
        return vulnerability + "|" + snapshotId;
    }

    private static ResultSet rows(Object[]... values) {
        int[] cursor = {-1};
        return proxy(ResultSet.class, (proxy, method, arguments) -> switch (method.getName()) {
            case "next" -> ++cursor[0] < values.length;
            case "getObject" -> values[cursor[0]][(Integer) arguments[0] - 1];
            case "getString" -> {
                Object value = values[cursor[0]][(Integer) arguments[0] - 1];
                yield value == null ? null : value.toString();
            }
            case "getDate" -> (Date) values[cursor[0]][(Integer) arguments[0] - 1];
            case "getInt" -> ((Number) values[cursor[0]][(Integer) arguments[0] - 1]).intValue();
            case "close" -> null;
            default -> defaultValue(method.getReturnType());
        });
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler);
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == double.class) return 0D;
        if (type == float.class) return 0F;
        if (type == short.class) return (short) 0;
        if (type == byte.class) return (byte) 0;
        if (type == char.class) return '\0';
        return null;
    }
}
