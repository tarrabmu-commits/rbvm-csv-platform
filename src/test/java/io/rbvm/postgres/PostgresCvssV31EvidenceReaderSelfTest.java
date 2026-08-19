package io.rbvm.postgres;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public final class PostgresCvssV31EvidenceReaderSelfTest {
    private PostgresCvssV31EvidenceReaderSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        readsCurrentPerSourceEvidenceWithTenantAndCveFilter();
        rejectsUnsafeQueryBounds();
        System.out.println("PostgresCvssV31EvidenceReaderSelfTest: PASS");
    }

    private static void readsCurrentPerSourceEvidenceWithTenantAndCveFilter() throws Exception {
        FakeDatabase database = new FakeDatabase();
        PostgresCvssV31EvidenceReader reader = new PostgresCvssV31EvidenceReader(database::connection);

        Map<String, Object> output = reader.currentEvidence(25, "cve-2026-");
        assert output.get("semantics").equals("CURRENT_PER_SOURCE_CVSS_V31_BASE_EVIDENCE");
        assert output.get("limit").equals(25);
        assert output.get("cvePrefix").equals("CVE-2026-");
        assert output.get("count").equals(1);
        assert database.lastSql.contains("rbvm.current_cvss_v31_base_evidence");
        assert database.lastSql.contains("JOIN rbvm.tenant");
        assert database.lastSql.contains("t.tenant_key = ?");
        assert database.parameters.get(1).equals("local");
        assert database.parameters.get(2).equals("CVE-2026-");
        assert database.parameters.get(3).equals("CVE-2026-%");
        assert database.parameters.get(4).equals(25);
    }

    private static void rejectsUnsafeQueryBounds() {
        PostgresCvssV31EvidenceReader reader = new PostgresCvssV31EvidenceReader(() -> {
            throw new AssertionError("Database must not be opened for rejected input");
        });
        boolean badLimit = false;
        try {
            reader.currentEvidence(0, null);
        } catch (Exception expected) {
            badLimit = expected instanceof IllegalArgumentException;
        }
        assert badLimit;

        boolean badCve = false;
        try {
            reader.currentEvidence(10, "not a cve");
        } catch (Exception expected) {
            badCve = expected instanceof IllegalArgumentException;
        }
        assert badCve;
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
                    "CVE-2026-25087",
                    "3.1",
                    new BigDecimal("8.1"),
                    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-25087",
                    Timestamp.from(Instant.parse("2026-08-19T08:00:00Z")),
                    Timestamp.from(Instant.parse("2026-08-19T08:01:00Z"))
            }};
            int[] cursor = {-1};
            return proxy(ResultSet.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "next" -> ++cursor[0] < values.length;
                case "getString" -> values[cursor[0]][(Integer) arguments[0] - 1].toString();
                case "getBigDecimal" -> values[cursor[0]][(Integer) arguments[0] - 1];
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
