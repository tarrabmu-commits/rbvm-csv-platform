package io.rbvm.postgres;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
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
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public final class PostgresCisaKevImporterSelfTest {
    private static final Instant NOW = Instant.parse("2026-08-19T10:30:00Z");
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID VULN_A = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static final UUID VULN_B = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private static final String CVE_A = "CVE-2026-10001";
    private static final String CVE_B = "CVE-2026-10002";
    private static final String FOREIGN_CVE = "CVE-2026-19999";
    private static final String SOURCE = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private static final String SHA_A = "a".repeat(64);
    private static final String SHA_B = "b".repeat(64);
    private static final String SHA_C = "c".repeat(64);

    private PostgresCisaKevImporterSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        importsSnapshotBoundHistoryAndQuarantinesConflictsWithoutChoosingWinners();
        System.out.println("PostgresCisaKevImporterSelfTest: PASS");
    }

    private static void importsSnapshotBoundHistoryAndQuarantinesConflictsWithoutChoosingWinners()
            throws Exception {
        Path first = Files.createTempFile("cisa-kev-import-", ".csv");
        Path persistedSnapshotConflict = Files.createTempFile("cisa-kev-snapshot-conflict-", ".csv");
        Path fileSnapshotConflict = Files.createTempFile("cisa-kev-file-conflict-", ".csv");
        try {
            Files.writeString(first, headers()
                    + listed(CVE_A, "2026.08.19", SHA_A, 2, "2026-08-19T09:00:00Z",
                            "2026-08-01", "2026-08-22", "KNOWN")
                    + listed(CVE_A, "2026.08.19", SHA_A, 2, "2026-08-19T09:00:00Z",
                            "2026-08-01", "2026-08-22", "KNOWN")
                    + notListed(CVE_B, "2026.08.19", SHA_A, 2, "2026-08-19T09:00:00Z")
                    + notListed(FOREIGN_CVE, "2026.08.19", SHA_A, 2,
                            "2026-08-19T09:00:00Z"),
                    StandardCharsets.UTF_8);

            Files.writeString(persistedSnapshotConflict, headers()
                    + listed(CVE_A, "2026.08.19-conflict", SHA_B, 2,
                            "2026-08-19T09:00:00Z", "2026-08-01", "2026-08-22", "KNOWN"),
                    StandardCharsets.UTF_8);

            // Same source and observation time but contradictory catalog identities across CVEs.
            // The importer must quarantine both rows instead of making row order a source policy.
            Files.writeString(fileSnapshotConflict, headers()
                    + listed(CVE_A, "2026.08.19-a", SHA_B, 2,
                            "2026-08-19T11:00:00Z", "2026-08-01", "2026-08-22", "KNOWN")
                    + notListed(CVE_B, "2026.08.19-b", SHA_C, 3,
                            "2026-08-19T11:00:00Z"),
                    StandardCharsets.UTF_8);

            FakeDatabase database = new FakeDatabase();
            database.vulnerabilities.put(CVE_A, VULN_A);
            database.vulnerabilities.put(CVE_B, VULN_B);
            PostgresCisaKevImporter importer = new PostgresCisaKevImporter(
                    database::connection,
                    false,
                    Clock.fixed(NOW, ZoneOffset.UTC)
            );

            CisaKevImportResult firstResult = importer.importFile(first);
            assert importer.schemaVersion() == 11;
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

            StoredEvidence listed = database.evidence.values().stream()
                    .filter(value -> value.status.equals("LISTED"))
                    .findFirst().orElseThrow();
            assert listed.dateAdded.equals(Date.valueOf("2026-08-01"));
            assert listed.dueDate.equals(Date.valueOf("2026-08-22"));
            assert listed.ransomware.equals("KNOWN");
            StoredEvidence notListed = database.evidence.values().stream()
                    .filter(value -> value.status.equals("NOT_LISTED"))
                    .findFirst().orElseThrow();
            assert notListed.dateAdded == null;
            assert notListed.dueDate == null;
            assert notListed.ransomware == null;

            CisaKevImportResult replay = importer.importFile(first);
            assert replay.insertedSnapshots() == 0;
            assert replay.replayedSnapshots() == 1;
            assert replay.insertedEvidence() == 0;
            assert replay.replayedEvidence() == 2;
            assert replay.persistenceQuarantinedRows() == 1;
            assert database.snapshots.size() == 1;
            assert database.evidence.size() == 2;
            assert database.catalogRevision == 1 : "pure replay must not change catalog revision";

            CisaKevImportResult persistedConflict = importer.importFile(persistedSnapshotConflict);
            assert persistedConflict.insertedSnapshots() == 0;
            assert persistedConflict.replayedSnapshots() == 0;
            assert persistedConflict.snapshotConflictGroups() == 1;
            assert persistedConflict.insertedEvidence() == 0;
            assert persistedConflict.persistenceQuarantinedRows() == 1;
            assert persistedConflict.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals(
                            "CONFLICTING_PERSISTED_KEV_SNAPSHOT_TIMESTAMP"));
            assert database.snapshots.size() == 1;
            assert database.evidence.size() == 2;
            assert database.catalogRevision == 1;

            CisaKevImportResult fileConflict = importer.importFile(fileSnapshotConflict);
            assert fileConflict.insertedSnapshots() == 0;
            assert fileConflict.replayedSnapshots() == 0;
            assert fileConflict.snapshotConflictGroups() == 1;
            assert fileConflict.insertedEvidence() == 0;
            assert fileConflict.replayedEvidence() == 0;
            assert fileConflict.persistenceQuarantinedRows() == 2;
            assert fileConflict.persistenceIssues().stream()
                    .filter(issue -> issue.code().equals("CONFLICTING_KEV_SNAPSHOT_TIMESTAMP"))
                    .count() == 2;
            assert database.snapshots.size() == 1
                    : "contradictory in-file snapshot rows must not create a snapshot";
            assert database.catalogRevision == 1;

            // A persisted membership conflict is quarantined rather than overwritten.
            String evidenceKey = database.evidence.keySet().stream()
                    .filter(key -> key.startsWith(VULN_A.toString()))
                    .findFirst().orElseThrow();
            StoredEvidence original = database.evidence.get(evidenceKey);
            database.evidence.put(evidenceKey, original.withSha("f".repeat(64)));
            CisaKevImportResult evidenceConflict = importer.importFile(first);
            assert evidenceConflict.replayedSnapshots() == 1;
            assert evidenceConflict.insertedEvidence() == 0;
            assert evidenceConflict.replayedEvidence() == 1;
            assert evidenceConflict.persistenceQuarantinedRows() == 2;
            assert evidenceConflict.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals(
                            "CONFLICTING_PERSISTED_KEV_EVIDENCE"));
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
        return "CVE_ID,KEV_Status,KEV_Catalog_Version,KEV_Catalog_SHA256,KEV_Catalog_Count,"
                + "KEV_Source,KEV_Observed_At,KEV_Date_Added,KEV_Due_Date,"
                + "Known_Ransomware_Campaign_Use\r\n";
    }

    private static String listed(
            String cve,
            String version,
            String sha,
            int count,
            String observedAt,
            String dateAdded,
            String dueDate,
            String ransomware
    ) {
        return cve + ",LISTED," + version + "," + sha + "," + count + "," + SOURCE + ","
                + observedAt + "," + dateAdded + "," + dueDate + "," + ransomware + "\r\n";
    }

    private static String notListed(
            String cve,
            String version,
            String sha,
            int count,
            String observedAt
    ) {
        return cve + ",NOT_LISTED," + version + "," + sha + "," + count + "," + SOURCE + ","
                + observedAt + ",,,\r\n";
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
                case "executeQuery" -> rows(new Object[]{11});
                case "close" -> null;
                default -> defaultValue(method.getReturnType());
            });
        }

        private PreparedStatement prepared(String sql) {
            Map<Integer, Object> parameters = new HashMap<>();
            return proxy(PreparedStatement.class, (proxy, method, arguments) -> {
                String name = method.getName();
                if (name.equals("setNull")) {
                    parameters.put((Integer) arguments[0], null);
                    return null;
                }
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
            if (sql.contains("FROM rbvm.cisa_kev_catalog_snapshot")) {
                String source = (String) parameters.get(2);
                Instant observedAt = ((Timestamp) parameters.get(3)).toInstant();
                StoredSnapshot stored = snapshots.get(snapshotKey(source, observedAt));
                return stored == null ? rows() : rows(new Object[]{
                        stored.id, stored.catalogVersion, stored.sha256, stored.count
                });
            }
            if (sql.contains("FROM rbvm.cisa_kev_evidence")) {
                UUID vulnerability = (UUID) parameters.get(2);
                UUID snapshotId = (UUID) parameters.get(3);
                StoredEvidence stored = evidence.get(evidenceKey(vulnerability, snapshotId));
                return stored == null ? rows() : rows(new Object[]{stored.sha256});
            }
            throw new AssertionError("Unexpected query:\n" + sql);
        }

        private int update(String sql, Map<Integer, Object> parameters) {
            if (sql.contains("INSERT INTO rbvm.cisa_kev_catalog_snapshot")) {
                UUID id = (UUID) parameters.get(1);
                String catalogVersion = (String) parameters.get(3);
                String sha256 = (String) parameters.get(4);
                int count = (Integer) parameters.get(5);
                String source = (String) parameters.get(6);
                Instant observedAt = ((Timestamp) parameters.get(7)).toInstant();
                String key = snapshotKey(source, observedAt);
                if (snapshots.putIfAbsent(
                        key,
                        new StoredSnapshot(id, catalogVersion, sha256, count, source, observedAt)
                ) != null) {
                    throw new AssertionError("Importer attempted duplicate KEV snapshot insert");
                }
                return 1;
            }
            if (sql.contains("INSERT INTO rbvm.cisa_kev_evidence")) {
                UUID vulnerability = (UUID) parameters.get(3);
                UUID snapshotId = (UUID) parameters.get(4);
                String status = (String) parameters.get(5);
                Date dateAdded = (Date) parameters.get(6);
                Date dueDate = (Date) parameters.get(7);
                String ransomware = (String) parameters.get(8);
                String sha256 = (String) parameters.get(10);
                String key = evidenceKey(vulnerability, snapshotId);
                if (evidence.putIfAbsent(
                        key,
                        new StoredEvidence(status, dateAdded, dueDate, ransomware, sha256)
                ) != null) {
                    throw new AssertionError("Importer attempted duplicate KEV evidence insert");
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
            String catalogVersion,
            String sha256,
            int count,
            String source,
            Instant observedAt
    ) {
    }

    private record StoredEvidence(
            String status,
            Date dateAdded,
            Date dueDate,
            String ransomware,
            String sha256
    ) {
        private StoredEvidence withSha(String replacement) {
            return new StoredEvidence(status, dateAdded, dueDate, ransomware, replacement);
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
