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

public final class PostgresBusinessImpactImporterSelfTest {
    private static final Instant NOW = Instant.parse("2026-08-19T19:00:00Z");
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID ASSET_A = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static final UUID ASSET_B = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private static final String SOURCE = "BIA-2026";
    private static final String SHA_A = "a".repeat(64);
    private static final String SHA_B = "b".repeat(64);
    private static final String SHA_C = "c".repeat(64);

    private PostgresBusinessImpactImporterSelfTest() {}

    public static void main(String[] args) throws Exception {
        importsQualitativeImpactAndQuarantinesConflicts();
        System.out.println("PostgresBusinessImpactImporterSelfTest: PASS");
    }

    private static void importsQualitativeImpactAndQuarantinesConflicts() throws Exception {
        Path first = Files.createTempFile("business-impact-import-", ".csv");
        Path persistedSnapshotConflict = Files.createTempFile("business-impact-snapshot-conflict-", ".csv");
        Path fileSnapshotConflict = Files.createTempFile("business-impact-file-conflict-", ".csv");
        try {
            Files.writeString(first, headers()
                    + nameRow("web-01", "Checkout", "AVAILABILITY", "SEVERE", "BUSINESS_IMPACT_ANALYSIS",
                            "Checkout outage stops purchases", "2026-08-19T09:00:00Z", SHA_A)
                    + nameRow("WEB-01", " checkout ", "AVAILABILITY", "SEVERE", "BUSINESS_IMPACT_ANALYSIS",
                            "Checkout outage stops purchases", "2026-08-19T09:00:00Z", SHA_A)
                    + stableRow("db-display", "agent-db-02", "Settlement", "REGULATORY", "HIGH",
                            "POLICY_CLASSIFICATION", "Settlement processing is regulated", "2026-08-19T09:00:00Z", SHA_A)
                    + nameRow("ghost-asset", "Checkout", "MISSION", "UNKNOWN", "SERVICE_OWNER_ATTESTATION",
                            "Mission impact is under review", "2026-08-19T09:00:00Z", SHA_A), StandardCharsets.UTF_8);
            Files.writeString(persistedSnapshotConflict, headers()
                    + nameRow("web-01", "Checkout", "AVAILABILITY", "LOW", "BUSINESS_IMPACT_ANALYSIS",
                            "Different artifact", "2026-08-19T09:00:00Z", SHA_B), StandardCharsets.UTF_8);
            Files.writeString(fileSnapshotConflict, headers()
                    + nameRow("web-01", "Checkout", "MISSION", "HIGH", "SERVICE_OWNER_ATTESTATION",
                            "Mission dependency", "2026-08-19T11:00:00Z", SHA_B)
                    + stableRow("db-display", "agent-db-02", "Settlement", "FINANCIAL", "MODERATE",
                            "INCIDENT_ANALYSIS", "Historical settlement delay", "2026-08-19T11:00:00Z", SHA_C),
                    StandardCharsets.UTF_8);

            FakeDatabase database = new FakeDatabase();
            database.assets.put(assetKey("wazuh-primary", "SOURCE_NAME_ONLY", "web-01"), ASSET_A);
            database.assets.put(assetKey("wazuh-v2", "SOURCE_STABLE_ID", "agent-db-02"), ASSET_B);
            PostgresBusinessImpactImporter importer = new PostgresBusinessImpactImporter(
                    database::connection, false, Clock.fixed(NOW, ZoneOffset.UTC));

            BusinessImpactImportResult firstResult = importer.importFile(first);
            assert importer.schemaVersion() == 15;
            assert firstResult.analysis().logicalRows() == 4;
            assert firstResult.analysis().deduplicatedRows() == 1;
            assert firstResult.analysis().acceptedRows() == 3;
            assert firstResult.insertedSnapshots() == 1;
            assert firstResult.insertedEvidence() == 2;
            assert firstResult.persistenceQuarantinedRows() == 1;
            assert firstResult.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals("ASSET_NOT_FOUND_IN_TENANT"));
            assert database.snapshots.size() == 1;
            assert database.evidence.size() == 2;
            assert database.catalogRevision == 1;

            StoredSnapshot snapshot = database.snapshots.values().iterator().next();
            StoredEvidence availability = database.evidence.get(evidenceKey(
                    ASSET_A, snapshot.id, "checkout", "AVAILABILITY"));
            assert availability.businessService.equals("Checkout");
            assert availability.businessServiceNormalized.equals("checkout");
            assert availability.impactLevel.equals("SEVERE");
            assert availability.impactMethod.equals("BUSINESS_IMPACT_ANALYSIS");
            StoredEvidence regulatory = database.evidence.get(evidenceKey(
                    ASSET_B, snapshot.id, "settlement", "REGULATORY"));
            assert regulatory.assetIdentityBasis.equals("SOURCE_STABLE_ID");
            assert regulatory.assetSourceId.equals("agent-db-02");
            assert regulatory.impactLevel.equals("HIGH");

            BusinessImpactImportResult replay = importer.importFile(first);
            assert replay.insertedSnapshots() == 0;
            assert replay.replayedSnapshots() == 1;
            assert replay.insertedEvidence() == 0;
            assert replay.replayedEvidence() == 2;
            assert replay.persistenceQuarantinedRows() == 1;
            assert database.catalogRevision == 1;

            BusinessImpactImportResult persistedConflict = importer.importFile(persistedSnapshotConflict);
            assert persistedConflict.snapshotConflictGroups() == 1;
            assert persistedConflict.insertedEvidence() == 0;
            assert persistedConflict.persistenceQuarantinedRows() == 1;
            assert persistedConflict.persistenceIssues().stream().anyMatch(issue -> issue.code().equals(
                    "CONFLICTING_PERSISTED_BUSINESS_IMPACT_SNAPSHOT_TIMESTAMP"));
            assert database.catalogRevision == 1;

            BusinessImpactImportResult fileConflict = importer.importFile(fileSnapshotConflict);
            assert fileConflict.snapshotConflictGroups() == 1;
            assert fileConflict.persistenceQuarantinedRows() == 2;
            assert fileConflict.persistenceIssues().stream().filter(issue -> issue.code().equals(
                    "CONFLICTING_BUSINESS_IMPACT_SNAPSHOT_TIMESTAMP")).count() == 2;
            assert database.snapshots.size() == 1;

            String key = evidenceKey(ASSET_A, snapshot.id, "checkout", "AVAILABILITY");
            database.evidence.put(key, database.evidence.get(key).withSha("f".repeat(64)));
            BusinessImpactImportResult evidenceConflict = importer.importFile(first);
            assert evidenceConflict.replayedSnapshots() == 1;
            assert evidenceConflict.insertedEvidence() == 0;
            assert evidenceConflict.replayedEvidence() == 1;
            assert evidenceConflict.persistenceQuarantinedRows() == 2;
            assert evidenceConflict.persistenceIssues().stream().anyMatch(issue -> issue.code().equals(
                    "CONFLICTING_PERSISTED_BUSINESS_IMPACT_EVIDENCE"));
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
        return "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Business_Service,Impact_Dimension,Impact_Level,Impact_Method,Impact_Statement,Impact_Source,Impact_Observed_At,Impact_Source_SHA256\r\n";
    }

    private static String nameRow(String name, String service, String dimension, String level,
            String method, String statement, String observedAt, String sha) {
        return "wazuh-primary,SOURCE_NAME_ONLY," + name + ",," + service + "," + dimension + ","
                + level + "," + method + "," + statement + "," + SOURCE + "," + observedAt + "," + sha + "\r\n";
    }

    private static String stableRow(String name, String sourceId, String service, String dimension,
            String level, String method, String statement, String observedAt, String sha) {
        return "wazuh-v2,SOURCE_STABLE_ID," + name + "," + sourceId + "," + service + "," + dimension + ","
                + level + "," + method + "," + statement + "," + SOURCE + "," + observedAt + "," + sha + "\r\n";
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
                case "setTransactionIsolation" -> { if ((Integer) arguments[0] == Connection.TRANSACTION_SERIALIZABLE) serializableTransactions++; yield null; }
                case "setAutoCommit", "close" -> null;
                case "commit" -> { commits++; yield null; }
                case "rollback" -> { rollbacks++; yield null; }
                case "getAutoCommit" -> true;
                case "isClosed" -> false;
                default -> defaultValue(method.getReturnType());
            });
        }

        private Statement statement() {
            return proxy(Statement.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "executeQuery" -> rows(new Object[]{15});
                case "close" -> null;
                default -> defaultValue(method.getReturnType());
            });
        }

        private PreparedStatement prepared(String sql) {
            Map<Integer, Object> parameters = new HashMap<>();
            return proxy(PreparedStatement.class, (proxy, method, arguments) -> {
                if (method.getName().startsWith("set") && arguments != null && arguments.length >= 2
                        && arguments[0] instanceof Integer index) {
                    parameters.put(index, arguments[1]);
                    return null;
                }
                return switch (method.getName()) {
                    case "execute" -> false;
                    case "executeQuery" -> query(sql, parameters);
                    case "executeUpdate" -> update(sql, parameters);
                    case "close" -> null;
                    default -> defaultValue(method.getReturnType());
                };
            });
        }

        private ResultSet query(String sql, Map<Integer, Object> p) {
            if (sql.contains("SELECT id FROM rbvm.tenant")) return rows(new Object[]{TENANT_ID});
            if (sql.contains("JOIN rbvm.source_profile sp")) {
                UUID asset = assets.get(assetKey((String) p.get(2), (String) p.get(3), (String) p.get(4)));
                return asset == null ? rows() : rows(new Object[]{asset});
            }
            if (sql.contains("FROM rbvm.business_impact_snapshot")) {
                StoredSnapshot stored = snapshots.get(snapshotKey((String) p.get(2), ((Timestamp) p.get(3)).toInstant()));
                return stored == null ? rows() : rows(new Object[]{stored.id, stored.sourceSha256});
            }
            if (sql.contains("FROM rbvm.business_impact_evidence")) {
                StoredEvidence stored = evidence.get(evidenceKey((UUID) p.get(2), (UUID) p.get(3),
                        (String) p.get(4), (String) p.get(5)));
                return stored == null ? rows() : rows(new Object[]{stored.sha256});
            }
            throw new AssertionError("Unexpected query:\n" + sql);
        }

        private int update(String sql, Map<Integer, Object> p) {
            if (sql.contains("INSERT INTO rbvm.business_impact_snapshot")) {
                UUID id = (UUID) p.get(1); String source = (String) p.get(3); String sha = (String) p.get(4);
                Instant observedAt = ((Timestamp) p.get(5)).toInstant();
                if (snapshots.putIfAbsent(snapshotKey(source, observedAt), new StoredSnapshot(id, sha, observedAt)) != null)
                    throw new AssertionError("duplicate Business Impact snapshot insert");
                return 1;
            }
            if (sql.contains("INSERT INTO rbvm.business_impact_evidence")) {
                UUID asset = (UUID) p.get(3); UUID snapshot = (UUID) p.get(4);
                String service = (String) p.get(8); String normalized = (String) p.get(9); String dimension = (String) p.get(10);
                StoredEvidence stored = new StoredEvidence((String) p.get(5), (String) p.get(7), service, normalized,
                        dimension, (String) p.get(11), (String) p.get(12), (String) p.get(13), (String) p.get(15));
                if (evidence.putIfAbsent(evidenceKey(asset, snapshot, normalized, dimension), stored) != null)
                    throw new AssertionError("duplicate Business Impact evidence insert");
                return 1;
            }
            if (sql.contains("UPDATE rbvm.catalog_state")) { catalogRevision++; return 1; }
            throw new AssertionError("Unexpected update:\n" + sql);
        }
    }

    private record StoredSnapshot(UUID id, String sourceSha256, Instant observedAt) {}
    private record StoredEvidence(String assetIdentityBasis, String assetSourceId, String businessService,
            String businessServiceNormalized, String impactDimension, String impactLevel,
            String impactMethod, String impactStatement, String sha256) {
        private StoredEvidence withSha(String replacement) {
            return new StoredEvidence(assetIdentityBasis, assetSourceId, businessService,
                    businessServiceNormalized, impactDimension, impactLevel, impactMethod, impactStatement, replacement);
        }
    }

    private static String assetKey(String profile, String basis, String identity) { return profile + "|" + basis + "|" + identity; }
    private static String snapshotKey(String source, Instant at) { return source + "|" + at; }
    private static String evidenceKey(UUID asset, UUID snapshot, String service, String dimension) {
        return asset + "|" + snapshot + "|" + service + "|" + dimension;
    }

    private static ResultSet rows(Object[]... values) {
        int[] cursor = {-1};
        return proxy(ResultSet.class, (proxy, method, arguments) -> switch (method.getName()) {
            case "next" -> ++cursor[0] < values.length;
            case "getObject" -> values[cursor[0]][(Integer) arguments[0] - 1];
            case "getString" -> { Object value = values[cursor[0]][(Integer) arguments[0] - 1]; yield value == null ? null : value.toString(); }
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
