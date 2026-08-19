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

public final class PostgresAssetContextEvidenceReaderSelfTest {
    private PostgresAssetContextEvidenceReaderSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        readsCurrentPerSourceContextWithTenantAndOperationalFilters();
        rejectsUnsafeQueryBounds();
        System.out.println("PostgresAssetContextEvidenceReaderSelfTest: PASS");
    }

    private static void readsCurrentPerSourceContextWithTenantAndOperationalFilters()
            throws Exception {
        FakeDatabase database = new FakeDatabase();
        PostgresAssetContextEvidenceReader reader =
                new PostgresAssetContextEvidenceReader(database::connection);

        Map<String, Object> output = reader.currentEvidence(
                25,
                " WEB-",
                "wazuh-primary",
                "CMDB inventory export"
        );
        assert output.get("semantics").equals(
                "CURRENT_PER_SOURCE_ASSET_ORGANIZATIONAL_CONTEXT_EVIDENCE");
        assert output.get("limit").equals(25);
        assert output.get("assetPrefix").equals("web-");
        assert output.get("sourceProfileKey").equals("wazuh-primary");
        assert output.get("contextSource").equals("CMDB inventory export");
        assert output.get("count").equals(1);
        assert database.lastSql.contains("rbvm.current_asset_context_evidence");
        assert database.lastSql.contains("JOIN rbvm.tenant");
        assert database.lastSql.contains("t.tenant_key = ?");
        assert database.lastSql.contains("lower(e.asset_name_observed) LIKE ?");
        assert database.lastSql.contains("e.source_profile_key = ?");
        assert database.lastSql.contains("e.context_source = ?");
        assert database.lastSql.contains("ORDER BY e.observed_at DESC");
        assert database.parameters.get(1).equals("local");
        assert database.parameters.get(2).equals("web-");
        assert database.parameters.get(3).equals("web-%");
        assert database.parameters.get(4).equals("web-%");
        assert database.parameters.get(5).equals("wazuh-primary");
        assert database.parameters.get(6).equals("wazuh-primary");
        assert database.parameters.get(7).equals("CMDB inventory export");
        assert database.parameters.get(8).equals("CMDB inventory export");
        assert database.parameters.get(9).equals(25);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) output.get("items");
        Map<String, Object> item = items.get(0);
        assert item.get("sourceProfileKey").equals("wazuh-primary");
        assert item.get("assetIdentityBasis").equals("SOURCE_NAME_ONLY");
        assert item.get("assetName").equals("web-01");
        assert item.get("assetSourceId") == null;
        assert item.get("environment").equals("PRODUCTION");
        assert item.get("businessService").equals("Checkout");
        assert item.get("businessOwner").equals("Payments Team");
        assert item.get("businessCriticality").equals("MISSION_CRITICAL");
        assert item.get("contextSource").equals("CMDB inventory export");
        assert item.get("contextSourceSha256").equals("a".repeat(64));
        assert item.get("contextObservedAt").equals("2026-08-19T09:00:00Z");
    }

    private static void rejectsUnsafeQueryBounds() {
        PostgresAssetContextEvidenceReader reader = new PostgresAssetContextEvidenceReader(() -> {
            throw new AssertionError("Database must not be opened for rejected input");
        });
        assertRejected(() -> reader.currentEvidence(0, null, null, null));
        assertRejected(() -> reader.currentEvidence(10, "x".repeat(161), null, null));
        assertRejected(() -> reader.currentEvidence(10, null, "bad profile!", null));
        assertRejected(() -> reader.currentEvidence(10, null, null, "x".repeat(257)));
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
        private String lastSql;
        private final Map<Integer, Object> parameters = new HashMap<>();

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
                    "wazuh-primary",
                    "SOURCE_NAME_ONLY",
                    "web-01",
                    null,
                    "PRODUCTION",
                    "Checkout",
                    "Payments Team",
                    "MISSION_CRITICAL",
                    "CMDB inventory export",
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
