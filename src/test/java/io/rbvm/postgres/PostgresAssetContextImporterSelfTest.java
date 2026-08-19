package io.rbvm.postgres;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
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

public final class PostgresAssetContextImporterSelfTest {
    private static final Instant NOW = Instant.parse("2026-08-19T17:00:00Z");
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID ASSET_A = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static final UUID ASSET_B = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private static final String SOURCE = "CMDB inventory export";
    private static final String SHA_A = "a".repeat(64);
    private static final String SHA_B = "b".repeat(64);
    private static final String SHA_C = "c".repeat(64);

    private PostgresAssetContextImporterSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        importsExistingAssetsAndQuarantinesSnapshotAndEvidenceConflicts();
        System.out.println("PostgresAssetContextImporterSelfTest: PASS");
    }

    private static void importsExistingAssetsAndQuarantinesSnapshotAndEvidenceConflicts()
            throws Exception {
        Path first = Files.createTempFile("asset-context-import-", ".csv");
        Path persistedSnapshotConflict = Files.createTempFile("asset-context-snapshot-conflict-", ".csv");
        Path fileSnapshotConflict = Files.createTempFile("asset-context-file-conflict-", ".csv");
        try {
            Files.writeString(first, headers()
                    + nameRow("web-01", "PRODUCTION", "Checkout", "Payments Team",
                            "MISSION_CRITICAL", "2026-08-19T09:00:00Z", SHA_A)
                    + nameRow("WEB-01", "PRODUCTION", "Checkout", "Payments Team",
                            "MISSION_CRITICAL", "2026-08-19T09:00:00Z", SHA_A)
                    + stableRow("db-display", "agent-db-02", "PRODUCTION", "Ledger",
                            "Database Team", "HIGH", "2026-08-19T09:00:00Z", SHA_A)
                    + nameRow("ghost-asset", "TEST", "Unknown Service", "Unknown Owner",
                            "LOW", "2026-08-19T09:00:00Z", SHA_A),
                    StandardCharsets.UTF_8);

            Files.writeString(persistedSnapshotConflict, headers()
                    + nameRow("web-01", "PRODUCTION", "Checkout", "Payments Team",
                            "HIGH", "2026-08-19T09:00:00Z", SHA_B),
                    StandardCharsets.UTF_8);

            // One semantic source observation cannot identify two different source artifacts.
            Files.writeString(fileSnapshotConflict, headers()
                    + nameRow("web-01", "PRODUCTION", "Checkout", "Payments Team",
                            "HIGH", "2026-08-19T11:00:00Z", SHA_B)
                    + stableRow("db-display", "agent-db-02", "PRODUCTION", "Ledger",
                            "Database Team", "HIGH", "2026-08-19T11:00:00Z", SHA_C),
                    StandardCharsets.UTF_8);

            FakeDatabase database = new FakeDatabase();
            database.assets.put(assetKey("wazuh-primary", "SOURCE_NAME_ONLY", "web-01"), ASSET_A);
            database.assets.put(assetKey("wazuh-v2", "SOURCE_STABLE_ID", "agent-db-02"), ASSET_B);

            PostgresAssetContextImporter importer = new PostgresAssetContextImporter(
                    database::connection,
                    false,
                    Clock.fixed(NOW, ZoneOffset.UTC)
            );

            AssetContextImportResult firstResult = importer.importFile(first);
            assert importer.schemaVersion() == 13;
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
                    .anyMatch(issue -> issue.code().equals("ASSET_NOT_FOUND_IN_TENANT"));
            assert database.snapshots.size() == 1;
            assert database.evidence.size() == 2;
            assert database.catalogRevision == 1;

            StoredSnapshot snapshot = database.snapshots.values().iterator().next();
            assert snapshot.sourceSha256.equals(SHA_A);
            assert snapshot.observedAt.equals(Instant.parse("2026-08-19T09:00:00Z"));
            StoredEvidence evidenceA = database.evidence.get(evidenceKey(ASSET_A, snapshot.id));
            assert evidenceA.environment.equals("PRODUCTION");
            assert evidenceA.businessCriticality.equals("MISSION_CRITICAL");
            StoredEvidence evidenceB = database.evidence.get(evidenceKey(ASSET_B, snapshot.id));
            assert evidenceB.assetIdentityBasis.equals("SOURCE_STABLE_ID");
            assert evidenceB.assetSourceId.equals("agent-db-02");

            AssetContextImportResult replay = importer.importFile(first);
            assert replay.insertedSnapshots() == 0;
            assert replay.replayedSnapshots() == 1;
            assert replay.insertedEvidence() == 0;
            assert replay.replayedEvidence() == 2;
            assert replay.persistenceQuarantinedRows() == 1;
            assert database.catalogRevision == 1 : "pure replay must not change catalog revision";

            AssetContextImportResult persistedConflict = importer.importFile(persistedSnapshotConflict);
            assert persistedConflict.insertedSnapshots() == 0;
            assert persistedConflict.replayedSnapshots() == 0;
            assert persistedConflict.snapshotConflictGroups() == 1;
            assert persistedConflict.insertedEvidence() == 0;
            assert persistedConflict.persistenceQuarantinedRows() == 1;
            assert persistedConflict.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals(
                            "CONFLICTING_PERSISTED_ASSET_CONTEXT_SNAPSHOT_TIMESTAMP"));
            assert database.snapshots.size() == 1;
            assert database.catalogRevision == 1;

            AssetContextImportResult fileConflict = importer.importFile(fileSnapshotConflict);
            assert fileConflict.insertedSnapshots() == 0;
            assert fileConflict.replayedSnapshots() == 0;
            assert fileConflict.snapshotConflictGroups() == 1;
            assert fileConflict.insertedEvidence() == 0;
            assert fileConflict.replayedEvidence() == 0;
            assert fileConflict.persistenceQuarantinedRows() == 2;
            assert fileConflict.persistenceIssues().stream()
                    .filter(issue -> issue.code().equals(
                            "CONFLICTING_ASSET_CONTEXT_SNAPSHOT_TIMESTAMP"))
                    .count() == 2;
            assert database.snapshots.size() == 1;
            assert database.catalogRevision == 1;

            String storedKey = evidenceKey(ASSET_A, snapshot.id);
            StoredEvidence original = database.evidence.get(storedKey);
            database.evidence.put(storedKey, original.withSha("f".repeat(64)));
            AssetContextImportResult evidenceConflict = importer.importFile(first);
            assert evidenceConflict.replayedSnapshots() == 1;
            assert evidenceConflict.insertedEvidence() == 0;
            assert evidenceConflict.replayedEvidence() == 1;
            assert evidenceConflict.persistenceQuarantinedRows() == 2;
            assert evidenceConflict.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals(
                            "CONFLICTING_PERSISTED_ASSET_CONTEXT_EVIDENCE"));
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
        return "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Environment,"
                + "Business_Service,Business_Owner,Business_Criticality,Context_Source,"
                + "Context_Observed_At,Context_Source_SHA256\r\n";
    }

    private static String nameRow(
            String name,
            String environment,
            String service,
            String owner,
            String criticality,
            String observedAt,
            String sha
    ) {
        return "wazuh-primary,SOURCE_NAME_ONLY," + name + ",," + environment + ","
                + service + "," + owner + "," + criticality + "," + SOURCE + ","
                + observedAt + "," + sha + "\r\n";
    }

    private static String stableRow(
            String name,
            String sourceId,
            String environment,
            String service,
            String owner,
            String criticality,
            String observedAt,
            String sha
    ) {
        return "wazuh-v2,SOURCE_STABLE_ID," + name + "," + sourceId + "," + environment + ","
                + service + "," + owner + "," + criticality + "," + SOURCE + ","
                + observedAt + "," + sha + "\r\n";
    }

    private static final class FakeDatabase {
        private final Map<String, UUID> assets = new HashMap<>();
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
                case "executeQuery" -> rows(new Object[]{13});
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
            if (sql.contains("JOIN rbvm.source_profile sp")) {
                UUID tenant = (UUID) parameters.get(1);
                String profile = (String) parameters.get(2);
                String basis = (String) parameters.get(3);
                String identity = (String) parameters.get(4);
                UUID asset = tenant.equals(TENANT_ID)
                        ? assets.get(assetKey(profile, basis, identity)) : null;
                return asset == null ? rows() : rows(new Object[]{asset});
            }
            if (sql.contains("FROM rbvm.asset_context_snapshot")) {
                String source = (String) parameters.get(2);
                Instant observedAt = ((Timestamp) parameters.get(3)).toInstant();
                StoredSnapshot stored = snapshots.get(snapshotKey(source, observedAt));
                return stored == null ? rows() : rows(new Object[]{stored.id, stored.sourceSha256});
            }
            if (sql.contains("FROM rbvm.asset_context_evidence")) {
                UUID asset = (UUID) parameters.get(2);
                UUID snapshotId = (UUID) parameters.get(3);
                StoredEvidence stored = evidence.get(evidenceKey(asset, snapshotId));
                return stored == null ? rows() : rows(new Object[]{stored.sha256});
            }
            throw new AssertionError("Unexpected query:\n" + sql);
        }

        private int update(String sql, Map<Integer, Object> parameters) {
            if (sql.contains("INSERT INTO rbvm.asset_context_snapshot")) {
                UUID id = (UUID) parameters.get(1);
                String source = (String) parameters.get(3);
                String sourceSha = (String) parameters.get(4);
                Instant observedAt = ((Timestamp) parameters.get(5)).toInstant();
                String key = snapshotKey(source, observedAt);
                if (snapshots.putIfAbsent(
                        key,
                        new StoredSnapshot(id, source, sourceSha, observedAt)
                ) != null) {
                    throw new AssertionError("Importer attempted duplicate asset context snapshot insert");
                }
                return 1;
            }
            if (sql.contains("INSERT INTO rbvm.asset_context_evidence")) {
                UUID asset = (UUID) parameters.get(3);
                UUID snapshotId = (UUID) parameters.get(4);
                String basis = (String) parameters.get(5);
                String sourceId = (String) parameters.get(7);
                String environment = (String) parameters.get(8);
                String criticality = (String) parameters.get(11);
                String sha256 = (String) parameters.get(13);
                String key = evidenceKey(asset, snapshotId);
                if (evidence.putIfAbsent(
                        key,
                        new StoredEvidence(basis, sourceId, environment, criticality, sha256)
                ) != null) {
                    throw new AssertionError("Importer attempted duplicate asset context evidence insert");
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
            String source,
            String sourceSha256,
            Instant observedAt
    ) {
    }

    private record StoredEvidence(
            String assetIdentityBasis,
            String assetSourceId,
            String environment,
            String businessCriticality,
            String sha256
    ) {
        private StoredEvidence withSha(String replacement) {
            return new StoredEvidence(
                    assetIdentityBasis, assetSourceId, environment, businessCriticality, replacement);
        }
    }

    private static String assetKey(String profile, String basis, String normalizedIdentity) {
        return profile + "|" + basis + "|" + normalizedIdentity;
    }

    private static String snapshotKey(String source, Instant observedAt) {
        return source + "|" + observedAt;
    }

    private static String evidenceKey(UUID asset, UUID snapshotId) {
        return asset + "|" + snapshotId;
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
