package io.rbvm.postgres;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class PostgresNetworkReachabilityEvidenceReaderSelfTest {
    private PostgresNetworkReachabilityEvidenceReaderSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        readsCurrentScopedEvidenceWithTenantAndOperationalFilters();
        preservesPortlessEvidenceAsNull();
        rejectsUnsafeQueryBoundsAndEnums();
        System.out.println("PostgresNetworkReachabilityEvidenceReaderSelfTest: PASS");
    }

    private static void readsCurrentScopedEvidenceWithTenantAndOperationalFilters()
            throws Exception {
        FakeDatabase database = new FakeDatabase(false);
        PostgresNetworkReachabilityEvidenceReader reader =
                new PostgresNetworkReachabilityEvidenceReader(database::connection);

        Map<String, Object> output = reader.currentEvidence(
                25,
                " WEB-",
                "wazuh-primary",
                "reachability-export",
                "internet",
                "reachable"
        );
        assert output.get("semantics").equals(
                "CURRENT_PER_SOURCE_SCOPED_NETWORK_REACHABILITY_EVIDENCE");
        assert output.get("limit").equals(25);
        assert output.get("assetPrefix").equals("web-");
        assert output.get("sourceProfileKey").equals("wazuh-primary");
        assert output.get("evidenceSource").equals("reachability-export");
        assert output.get("originScope").equals("INTERNET");
        assert output.get("reachabilityStatus").equals("REACHABLE");
        assert output.get("count").equals(1);
        assert database.lastSql.contains("rbvm.current_network_reachability_evidence");
        assert database.lastSql.contains("JOIN rbvm.tenant");
        assert database.lastSql.contains("t.tenant_key = ?");
        assert database.lastSql.contains("lower(e.asset_name_observed) LIKE ?");
        assert database.lastSql.contains("e.source_profile_key = ?");
        assert database.lastSql.contains("e.evidence_source = ?");
        assert database.lastSql.contains("e.origin_scope = ?");
        assert database.lastSql.contains("e.reachability_status = ?");
        assert database.lastSql.contains("COALESCE(e.target_port, 0)");
        assert database.parameters.get(1).equals("local");
        assert database.parameters.get(2).equals("web-");
        assert database.parameters.get(3).equals("web-%");
        assert database.parameters.get(4).equals("web-%");
        assert database.parameters.get(5).equals("wazuh-primary");
        assert database.parameters.get(6).equals("wazuh-primary");
        assert database.parameters.get(7).equals("reachability-export");
        assert database.parameters.get(8).equals("reachability-export");
        assert database.parameters.get(9).equals("INTERNET");
        assert database.parameters.get(10).equals("INTERNET");
        assert database.parameters.get(11).equals("REACHABLE");
        assert database.parameters.get(12).equals("REACHABLE");
        assert database.parameters.get(13).equals(25);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) output.get("items");
        Map<String, Object> item = items.get(0);
        assert item.get("sourceProfileKey").equals("wazuh-primary");
        assert item.get("assetIdentityBasis").equals("SOURCE_NAME_ONLY");
        assert item.get("assetName").equals("web-01");
        assert item.get("assetSourceId") == null;
        assert item.get("originScope").equals("INTERNET");
        assert item.get("originLabel").equals("public-probes");
        assert item.get("transportProtocol").equals("TCP");
        assert item.get("targetPort").equals(443);
        assert item.get("targetService").equals("https");
        assert item.get("reachabilityStatus").equals("REACHABLE");
        assert item.get("reachabilityMethod").equals("ACTIVE_PROBE");
        assert item.get("evidenceSource").equals("reachability-export");
        assert item.get("evidenceSourceSha256").equals("a".repeat(64));
        assert item.get("evidenceObservedAt").equals("2026-08-19T09:00:00Z");
    }

    private static void preservesPortlessEvidenceAsNull() throws Exception {
        PostgresNetworkReachabilityEvidenceReader reader =
                new PostgresNetworkReachabilityEvidenceReader(new FakeDatabase(true)::connection);
        Map<String, Object> output = reader.currentEvidence(10, null, null, null, null, null);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) output.get("items");
        assert items.get(0).get("transportProtocol").equals("ICMP");
        assert items.get(0).get("targetPort") == null;
        assert items.get(0).get("reachabilityStatus").equals("NOT_REACHABLE");
    }

    private static void rejectsUnsafeQueryBoundsAndEnums() {
        PostgresNetworkReachabilityEvidenceReader reader =
                new PostgresNetworkReachabilityEvidenceReader(() -> {
                    throw new AssertionError("Database must not be opened for rejected input");
                });
        assertRejected(() -> reader.currentEvidence(0, null, null, null, null, null));
        assertRejected(() -> reader.currentEvidence(10, "x".repeat(161), null, null, null, null));
        assertRejected(() -> reader.currentEvidence(10, null, "bad profile!", null, null, null));
        assertRejected(() -> reader.currentEvidence(10, null, null, "x".repeat(257), null, null));
        assertRejected(() -> reader.currentEvidence(10, null, null, null, "PUBLIC", null));
        assertRejected(() -> reader.currentEvidence(10, null, null, null, null, "OPEN"));
    }

    private static void assertRejected(ThrowingOperation operation) {
        boolean rejected = false;
        try {
            operation.run();
        } catch (Exception expected) {
            rejected = expected instanceof IllegalArgumentException;
        }
        assert rejected;
    }

    @FunctionalInterface
    private interface ThrowingOperation {
        void run() throws Exception;
    }

    private static final class FakeDatabase {
        private final boolean portless;
        private String lastSql;
        private final Map<Integer, Object> parameters = new HashMap<>();

        private FakeDatabase(boolean portless) {
            this.portless = portless;
        }

        private Connection connection() {
            return proxy(Connection.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "prepareStatement" -> prepared((String) arguments[0]);
                case "close" -> null;
                case "isClosed" -> false;
                default -> defaultValue(method.getReturnType());
            });
        }

        private PreparedStatement prepared(String sql) {
            lastSql = sql;
            return proxy(PreparedStatement.class, (proxy, method, arguments) -> {
                String name = method.getName();
                if (name.startsWith("set") && arguments != null && arguments.length >= 2
                        && arguments[0] instanceof Integer index) {
                    parameters.put(index, arguments[1]);
                    return null;
                }
                return switch (name) {
                    case "executeQuery" -> rows();
                    case "close" -> null;
                    default -> defaultValue(method.getReturnType());
                };
            });
        }

        private ResultSet rows() {
            Object[][] values = {{
                    portless ? "wazuh-v2" : "wazuh-primary",
                    portless ? "SOURCE_STABLE_ID" : "SOURCE_NAME_ONLY",
                    portless ? "db-display" : "web-01",
                    portless ? "agent-db-02" : null,
                    portless ? "INTERNAL_ENTERPRISE" : "INTERNET",
                    portless ? "corp-network" : "public-probes",
                    portless ? "ICMP" : "TCP",
                    portless ? null : 443,
                    portless ? "icmp" : "https",
                    portless ? "NOT_REACHABLE" : "REACHABLE",
                    portless ? "FIREWALL_POLICY" : "ACTIVE_PROBE",
                    "reachability-export",
                    "a".repeat(64),
                    Timestamp.from(Instant.parse("2026-08-19T09:00:00Z")),
                    Timestamp.from(Instant.parse("2026-08-19T09:01:00Z")),
                    Timestamp.from(Instant.parse("2026-08-19T09:01:00Z"))
            }};
            int[] cursor = {-1};
            return proxy(ResultSet.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "next" -> ++cursor[0] < values.length;
                case "getString" -> {
                    Object value = values[cursor[0]][(Integer) arguments[0] - 1];
                    yield value == null ? null : value.toString();
                }
                case "getObject" -> values[cursor[0]][(Integer) arguments[0] - 1];
                case "getTimestamp" -> values[cursor[0]][(Integer) arguments[0] - 1];
                case "close" -> null;
                default -> defaultValue(method.getReturnType());
            });
        }
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
