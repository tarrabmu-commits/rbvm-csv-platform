package io.rbvm.postgres;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public final class PostgresApplicabilityFindingExporterSelfTest {
    private static final UUID TENANT = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID FINDING = UUID.fromString("20000000-0000-5000-8000-000000000001");

    private PostgresApplicabilityFindingExporterSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exportsCanonicalFindingUuidAndCurrentApplicability();
        System.out.println("PostgresApplicabilityFindingExporterSelfTest: PASS");
    }

    private static void exportsCanonicalFindingUuidAndCurrentApplicability() throws Exception {
        PostgresApplicabilityFindingExporter exporter = new PostgresApplicabilityFindingExporter(
                PostgresApplicabilityFindingExporterSelfTest::connection
        );
        String csv = new String(exporter.exportCsv(), StandardCharsets.UTF_8);
        assert csv.startsWith("Finding_ID,Agent,CVE_ID,Affected_Product,Severity,");
        assert csv.contains("Current_Applicability_Status");
        assert csv.contains(FINDING.toString());
        assert csv.contains("agent-a");
        assert csv.contains("CVE-2026-25087");
        assert csv.contains("pyarrow");
        assert csv.contains("NOT_APPLICABLE");
        assert csv.contains("Vendor advisory");
        assert csv.contains("2026-08-19T07:00:00Z");
        assert !csv.contains(",Applicability_Status,")
                : "reference export must not masquerade as APPLICABILITY_CSV_V1";
    }

    private static Connection connection() {
        return proxy(Connection.class, (proxy, method, arguments) -> switch (method.getName()) {
            case "prepareStatement" -> prepared((String) arguments[0]);
            case "close" -> null;
            case "isClosed" -> false;
            default -> defaultValue(method.getReturnType());
        });
    }

    private static PreparedStatement prepared(String sql) {
        Map<Integer, Object> parameters = new LinkedHashMap<>();
        return proxy(PreparedStatement.class, (proxy, method, arguments) -> {
            String name = method.getName();
            if (name.startsWith("set") && arguments != null && arguments.length >= 2
                    && arguments[0] instanceof Integer index) {
                parameters.put(index, arguments[1]);
                return null;
            }
            return switch (name) {
                case "executeQuery" -> {
                    assert parameters.get(1) != null : "tenant parameter must be bound";
                    if (sql.contains("SELECT id FROM rbvm.tenant")) {
                        yield rows(Map.of("id", TENANT));
                    }
                    if (sql.contains("FROM rbvm.finding_applicability")) {
                        Map<String, Object> row = new LinkedHashMap<>();
                        row.put("finding_id", FINDING);
                        row.put("asset_name", "agent-a");
                        row.put("cve_id", "CVE-2026-25087");
                        row.put("product_name", "pyarrow");
                        row.put("current_severity", "HIGH");
                        row.put("applicability_status", "NOT_APPLICABLE");
                        row.put("applicability_assessed", true);
                        row.put("applicability_reason", "Binding is not exposed");
                        row.put("applicability_evidence_source", "Vendor advisory");
                        row.put("applicability_evaluated_at",
                                Timestamp.from(Instant.parse("2026-08-19T07:00:00Z")));
                        yield rows(row);
                    }
                    throw new AssertionError("Unexpected query: " + sql);
                }
                case "close" -> null;
                default -> defaultValue(method.getReturnType());
            };
        });
    }

    @SafeVarargs
    private static ResultSet rows(Map<String, Object>... values) {
        int[] cursor = {-1};
        return proxy(ResultSet.class, (proxy, method, arguments) -> switch (method.getName()) {
            case "next" -> ++cursor[0] < values.length;
            case "getObject" -> {
                Object key = arguments[0];
                if (key instanceof Integer) {
                    yield values[cursor[0]].values().iterator().next();
                }
                yield values[cursor[0]].get(key.toString());
            }
            case "getString" -> {
                Object value = values[cursor[0]].get(arguments[0].toString());
                yield value == null ? null : value.toString();
            }
            case "getBoolean" -> (Boolean) values[cursor[0]].get(arguments[0].toString());
            case "getTimestamp" -> (Timestamp) values[cursor[0]].get(arguments[0].toString());
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
