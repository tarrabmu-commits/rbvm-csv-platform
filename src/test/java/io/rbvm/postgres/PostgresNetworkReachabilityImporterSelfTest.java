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

public final class PostgresNetworkReachabilityImporterSelfTest {
    private static final Instant NOW = Instant.parse("2026-08-19T18:00:00Z");
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID ASSET_A = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static final UUID ASSET_B = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private static final String SOURCE = "reachability-export";
    private static final String SHA_A = "a".repeat(64);
    private static final String SHA_B = "b".repeat(64);
    private static final String SHA_C = "c".repeat(64);

    private PostgresNetworkReachabilityImporterSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        importsScopedEndpointsAndQuarantinesConflicts();
        System.out.println("PostgresNetworkReachabilityImporterSelfTest: PASS");
    }

    private static void importsScopedEndpointsAndQuarantinesConflicts() throws Exception {
        Path first = Files.createTempFile("reachability-import-", ".csv");
        Path persistedSnapshotConflict = Files.createTempFile("reachability-snapshot-conflict-", ".csv");
        Path fileSnapshotConflict = Files.createTempFile("reachability-file-conflict-", ".csv");
        try {
            Files.writeString(first, headers()
                    + tcpNameRow("web-01", "INTERNET", "public-probes", 443, "https",
                            "REACHABLE", "ACTIVE_PROBE", "2026-08-19T09:00:00Z", SHA_A)
                    + tcpNameRow("WEB-01", "INTERNET", "public-probes", 443, "https",
                            "REACHABLE", "ACTIVE_PROBE", "2026-08-19T09:00:00Z", SHA_A)
                    + icmpStableRow("db-display", "agent-db-02", "INTERNAL_ENTERPRISE",
                            "corp-network", "icmp", "NOT_REACHABLE", "FIREWALL_POLICY",
                            "2026-08-19T09:00:00Z", SHA_A)
                    + tcpNameRow("ghost-asset", "INTERNET", "public-probes", 22, "ssh",
                            "UNKNOWN", "PASSIVE_OBSERVATION", "2026-08-19T09:00:00Z", SHA_A),
                    StandardCharsets.UTF_8);

            Files.writeString(persistedSnapshotConflict, headers()
                    + tcpNameRow("web-01", "INTERNET", "public-probes", 443, "https",
                            "NOT_REACHABLE", "ACTIVE_PROBE", "2026-08-19T09:00:00Z", SHA_B),
                    StandardCharsets.UTF_8);

            Files.writeString(fileSnapshotConflict, headers()
                    + tcpNameRow("web-01", "INTERNET", "public-probes", 443, "https",
                            "REACHABLE", "ACTIVE_PROBE", "2026-08-19T11:00:00Z", SHA_B)
                    + icmpStableRow("db-display", "agent-db-02", "INTERNAL_ENTERPRISE",
                            "corp-network", "icmp", "NOT_REACHABLE", "FIREWALL_POLICY",
                            "2026-08-19T11:00:00Z", SHA_C),
                    StandardCharsets.UTF_8);

            FakeDatabase database = new FakeDatabase();
            database.assets.put(assetKey("wazuh-primary", "SOURCE_NAME_ONLY", "web-01"), ASSET_A);
            database.assets.put(assetKey("wazuh-v2", "SOURCE_STABLE_ID", "agent-db-02"), ASSET_B);

            PostgresNetworkReachabilityImporter importer = new PostgresNetworkReachabilityImporter(
                    database::connection,
                    false,
                    Clock.fixed(NOW, ZoneOffset.UTC)
            );

            NetworkReachabilityImportResult firstResult = importer.importFile(first);
            assert importer.schemaVersion() == 14;
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
            StoredEvidence tcp = database.evidence.get(evidenceKey(
                    ASSET_A, snapshot.id, "INTERNET", "public-probes", "TCP", 443));
            assert tcp.targetService.equals("https");
            assert tcp.reachabilityStatus.equals("REACHABLE");
            StoredEvidence icmp = database.evidence.get(evidenceKey(
                    ASSET_B, snapshot.id, "INTERNAL_ENTERPRISE", "corp-network", "ICMP", null));
            assert icmp.assetIdentityBasis.equals("SOURCE_STABLE_ID");
            assert icmp.assetSourceId.equals("agent-db-02");
            assert icmp.targetPort == null;
            assert icmp.reachabilityStatus.equals("NOT_REACHABLE");

            NetworkReachabilityImportResult replay = importer.importFile(first);
            assert replay.insertedSnapshots() == 0;
            assert replay.replayedSnapshots() == 1;
            assert replay.insertedEvidence() == 0;
            assert replay.replayedEvidence() == 2;
            assert replay.persistenceQuarantinedRows() == 1;
            assert database.catalogRevision == 1 : "pure replay must not change catalog revision";

            NetworkReachabilityImportResult persistedConflict =
                    importer.importFile(persistedSnapshotConflict);
            assert persistedConflict.insertedSnapshots() == 0;
            assert persistedConflict.replayedSnapshots() == 0;
            assert persistedConflict.snapshotConflictGroups() == 1;
            assert persistedConflict.insertedEvidence() == 0;
            assert persistedConflict.persistenceQuarantinedRows() == 1;
            assert persistedConflict.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals(
                            "CONFLICTING_PERSISTED_NETWORK_REACHABILITY_SNAPSHOT_TIMESTAMP"));
            assert database.snapshots.size() == 1;
            assert database.catalogRevision == 1;

            NetworkReachabilityImportResult fileConflict = importer.importFile(fileSnapshotConflict);
            assert fileConflict.insertedSnapshots() == 0;
            assert fileConflict.replayedSnapshots() == 0;
            assert fileConflict.snapshotConflictGroups() == 1;
            assert fileConflict.insertedEvidence() == 0;
            assert fileConflict.replayedEvidence() == 0;
            assert fileConflict.persistenceQuarantinedRows() == 2;
            assert fileConflict.persistenceIssues().stream()
                    .filter(issue -> issue.code().equals(
                            "CONFLICTING_NETWORK_REACHABILITY_SNAPSHOT_TIMESTAMP"))
                    .count() == 2;
            assert database.snapshots.size() == 1;
            assert database.catalogRevision == 1;

            String tcpKey = evidenceKey(
                    ASSET_A, snapshot.id, "INTERNET", "public-probes", "TCP", 443);
            StoredEvidence original = database.evidence.get(tcpKey);
            database.evidence.put(tcpKey, original.withSha("f".repeat(64)));
            NetworkReachabilityImportResult evidenceConflict = importer.importFile(first);
            assert evidenceConflict.replayedSnapshots() == 1;
            assert evidenceConflict.insertedEvidence() == 0;
            assert evidenceConflict.replayedEvidence() == 1;
            assert evidenceConflict.persistenceQuarantinedRows() == 2;
            assert evidenceConflict.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals(
                            "CONFLICTING_PERSISTED_NETWORK_REACHABILITY_EVIDENCE"));
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
        return "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Origin_Scope,"
                + "Origin_Label,Transport_Protocol,Target_Port,Target_Service,Reachability_Status,"
                + "Reachability_Method,Evidence_Source,Evidence_Observed_At,Evidence_Source_SHA256\r\n";
    }

    private static String tcpNameRow(
            String name,
            String originScope,
            String originLabel,
            int port,
            String service,
            String status,
            String method,
            String observedAt,
            String sha
    ) {
        return "wazuh-primary,SOURCE_NAME_ONLY," + name + ",," + originScope + ","
                + originLabel + ",TCP," + port + "," + service + "," + status + "," + method
                + "," + SOURCE + "," + observedAt + "," + sha + "\r\n";
    }

    private static String icmpStableRow(
            String name,
            String sourceId,
            String originScope,
            String originLabel,
            String service,
            String status,
            String method,
            String observedAt,
            String sha
    ) {
        return "wazuh-v2,SOURCE_STABLE_ID," + name + "," + sourceId + "," + originScope + ","
                + originLabel + ",ICMP,," + service + "," + status + "," + method + ","
                + SOURCE + "," + observedAt + "," + sha + "\r\n";
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
                case "executeQuery" -> rows(new Object[]{14});
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
            if (sql.contains("FROM rbvm.network_reachability_snapshot")) {
                String source = (String) parameters.get(2);
                Instant observedAt = ((Timestamp) parameters.get(3)).toInstant();
                StoredSnapshot stored = snapshots.get(snapshotKey(source, observedAt));
                return stored == null ? rows() : rows(new Object[]{stored.id, stored.sourceSha256});
            }
            if (sql.contains("FROM rbvm.network_reachability_evidence")) {
                UUID asset = (UUID) parameters.get(2);
                UUID snapshotId = (UUID) parameters.get(3);
                String originScope = (String) parameters.get(4);
                String originLabel = (String) parameters.get(5);
                String protocol = (String) parameters.get(6);
                Integer port = (Integer) parameters.get(7);
                StoredEvidence stored = evidence.get(evidenceKey(
                        asset, snapshotId, originScope, originLabel, protocol, port));
                return stored == null ? rows() : rows(new Object[]{stored.sha256});
            }
            throw new AssertionError("Unexpected query:\n" + sql);
        }

        private int update(String sql, Map<Integer, Object> parameters) {
            if (sql.contains("INSERT INTO rbvm.network_reachability_snapshot")) {
                UUID id = (UUID) parameters.get(1);
                String source = (String) parameters.get(3);
                String sourceSha = (String) parameters.get(4);
                Instant observedAt = ((Timestamp) parameters.get(5)).toInstant();
                String key = snapshotKey(source, observedAt);
                if (snapshots.putIfAbsent(
                        key,
                        new StoredSnapshot(id, source, sourceSha, observedAt)
                ) != null) {
                    throw new AssertionError("Importer attempted duplicate reachability snapshot insert");
                }
                return 1;
            }
            if (sql.contains("INSERT INTO rbvm.network_reachability_evidence")) {
                UUID asset = (UUID) parameters.get(3);
                UUID snapshotId = (UUID) parameters.get(4);
                String basis = (String) parameters.get(5);
                String sourceId = (String) parameters.get(7);
                String originScope = (String) parameters.get(8);
                String originLabel = (String) parameters.get(9);
                String protocol = (String) parameters.get(10);
                Integer port = (Integer) parameters.get(11);
                String service = (String) parameters.get(12);
                String status = (String) parameters.get(13);
                String method = (String) parameters.get(14);
                String sha256 = (String) parameters.get(16);
                String key = evidenceKey(asset, snapshotId, originScope, originLabel, protocol, port);
                if (evidence.putIfAbsent(
                        key,
                        new StoredEvidence(basis, sourceId, port, service, status, method, sha256)
                ) != null) {
                    throw new AssertionError("Importer attempted duplicate reachability evidence insert");
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
            Integer targetPort,
            String targetService,
            String reachabilityStatus,
            String reachabilityMethod,
            String sha256
    ) {
        private StoredEvidence withSha(String replacement) {
            return new StoredEvidence(
                    assetIdentityBasis,
                    assetSourceId,
                    targetPort,
                    targetService,
                    reachabilityStatus,
                    reachabilityMethod,
                    replacement
            );
        }
    }

    private static String assetKey(String profile, String basis, String normalizedIdentity) {
        return profile + "|" + basis + "|" + normalizedIdentity;
    }

    private static String snapshotKey(String source, Instant observedAt) {
        return source + "|" + observedAt;
    }

    private static String evidenceKey(
            UUID asset,
            UUID snapshotId,
            String originScope,
            String originLabel,
            String protocol,
            Integer port
    ) {
        return asset + "|" + snapshotId + "|" + originScope + "|" + originLabel + "|"
                + protocol + "|" + (port == null ? "<null>" : port);
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
