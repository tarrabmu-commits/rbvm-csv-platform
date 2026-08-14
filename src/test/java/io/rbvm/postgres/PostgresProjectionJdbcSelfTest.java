package io.rbvm.postgres;

import io.rbvm.csv.AnalysisReport;
import io.rbvm.csv.ProjectionImport;
import io.rbvm.csv.WazuhCsvAnalyzer;
import io.rbvm.domain.CaseActionType;
import io.rbvm.domain.CaseAuditEvent;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.CaseStatus;
import io.rbvm.domain.DomainMaterializationResult;
import io.rbvm.domain.InMemoryDomainCatalog;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class PostgresProjectionJdbcSelfTest {
    private static final Instant NOW = Instant.parse("2026-07-20T12:00:00Z");
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID SOURCE_ID = UUID.fromString("10000000-0000-5000-8000-000000000002");
    private static final UUID ASSET_ID = UUID.fromString("10000000-0000-5000-8000-000000000003");
    private static final UUID VULNERABILITY_ID = UUID.fromString("10000000-0000-5000-8000-000000000004");
    private static final UUID COMPONENT_ID = UUID.fromString("10000000-0000-5000-8000-000000000005");
    private static final UUID OBSERVATION_ID = UUID.fromString("10000000-0000-5000-8000-000000000006");
    private static final UUID CASE_ID = UUID.fromString("10000000-0000-5000-8000-000000000007");
    private static final UUID EXPOSURE_ID = UUID.fromString("10000000-0000-5000-8000-000000000008");

    private PostgresProjectionJdbcSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        bindsEveryJdbcParameterAndCommitsBothTransactions();
        System.out.println("PostgresProjectionJdbcSelfTest: PASS");
    }

    private static void bindsEveryJdbcParameterAndCommitsBothTransactions() throws Exception {
        Path csv = Files.createTempFile("rbvm-postgres-projection-", ".csv");
        try {
            Files.writeString(csv, """
                    Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At
                    agent-a,CVE-2026-1234,High,description,pkg-a,https://example.test/1,Ubuntu,2026-07-01T10:15:30Z
                    """, StandardCharsets.UTF_8);
            UUID importId = UUID.fromString("20000000-0000-5000-8000-000000000001");
            String profile = "jdbc-contract";
            AnalysisReport analysis = new WazuhCsvAnalyzer(profile).analyze(csv, 0);
            InMemoryDomainCatalog local = new InMemoryDomainCatalog();
            DomainMaterializationResult localResult = local.materialize(importId, csv, profile);
            Map<String, Object> localCase = local.queryCases(CaseQuery.firstPage(1)).cases().get(0);
            String casePublicId = localCase.get("caseId").toString();

            FakeProjectionDatabase database = new FakeProjectionDatabase();
            Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
            PostgresCanonicalProjection projection = new PostgresCanonicalProjection(
                    database::connection,
                    false,
                    clock
            );
            projection.synchronizeImport(new ProjectionImport(
                    importId,
                    csv,
                    profile,
                    analysis,
                    localResult,
                    NOW.minusSeconds(60)
            ));
            projection.synchronizeCaseEvent(new CaseAuditEvent(
                    1,
                    "a".repeat(64),
                    casePublicId,
                    1,
                    "jdbc-event-0001",
                    "b".repeat(64),
                    CaseActionType.COMMENT,
                    CaseStatus.OPEN,
                    CaseStatus.OPEN,
                    "JDBC binding contract",
                    null,
                    null,
                    "local-operator",
                    "UNAUTHENTICATED_LOCAL",
                    NOW
            ));

            Map<String, Object> health = projection.health();
            assert health.get("status").equals("UP") : health;
            assert health.get("schemaVersion").equals(5);
            assert database.commits == 2;
            assert database.rollbacks == 0;
            assert database.verifiedExecutions >= 30 : database.verifiedExecutions;
            assert database.serializableTransactions == 2;
        } finally {
            Files.deleteIfExists(csv);
        }
    }

    private static final class FakeProjectionDatabase {
        private int commits;
        private int rollbacks;
        private int verifiedExecutions;
        private int serializableTransactions;
        private boolean initialized;

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
                case "commit" -> {
                    commits++;
                    yield null;
                }
                case "rollback" -> {
                    rollbacks++;
                    yield null;
                }
                case "setAutoCommit", "close" -> null;
                case "getAutoCommit" -> true;
                case "isClosed" -> false;
                default -> defaultValue(method.getReturnType());
            });
        }

        private Statement statement() {
            return proxy(Statement.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "executeQuery" -> rows(new Object[]{5});
                case "close" -> null;
                default -> defaultValue(method.getReturnType());
            });
        }

        private PreparedStatement prepared(String sql) {
            int placeholders = (int) sql.chars().filter(value -> value == '?').count();
            Map<Integer, Object> parameters = new HashMap<>();
            return proxy(PreparedStatement.class, (proxy, method, arguments) -> {
                String name = method.getName();
                if (name.startsWith("set") && arguments != null && arguments.length >= 2
                        && arguments[0] instanceof Integer index) {
                    parameters.put(index, arguments[1]);
                    return null;
                }
                return switch (name) {
                    case "execute", "executeUpdate", "executeQuery" -> {
                        for (int index = 1; index <= placeholders; index++) {
                            if (!parameters.containsKey(index)) {
                                throw new AssertionError(
                                        "SQL parameter " + index + " was not bound:\n" + sql);
                            }
                        }
                        verifiedExecutions++;
                        if (name.equals("execute")) {
                            yield false;
                        }
                        if (name.equals("executeUpdate")) {
                            yield 1;
                        }
                        yield queryResult(sql);
                    }
                    case "close" -> null;
                    default -> defaultValue(method.getReturnType());
                };
            });
        }

        private ResultSet queryResult(String sql) {
            if (sql.contains("INSERT INTO rbvm.tenant")) {
                initialized = true;
                return rows(new Object[]{TENANT_ID});
            }
            if (sql.contains("INSERT INTO rbvm.source_profile")) {
                return rows(new Object[]{SOURCE_ID});
            }
            if (sql.contains("SELECT 1 FROM rbvm.domain_materialization")) {
                return rows();
            }
            if (sql.contains("SELECT id FROM rbvm.observation")) {
                return rows();
            }
            if (sql.contains("INSERT INTO rbvm.asset_component")) {
                return rows(new Object[]{COMPONENT_ID});
            }
            if (sql.contains("INSERT INTO rbvm.asset(")) {
                return rows(new Object[]{ASSET_ID});
            }
            if (sql.contains("INSERT INTO rbvm.vulnerability_case")) {
                return rows(new Object[]{CASE_ID});
            }
            if (sql.contains("INSERT INTO rbvm.vulnerability(")) {
                return rows(new Object[]{VULNERABILITY_ID});
            }
            if (sql.contains("INSERT INTO rbvm.observation(")) {
                return rows(new Object[]{OBSERVATION_ID});
            }
            if (sql.contains("INSERT INTO rbvm.exposure(")) {
                return rows(new Object[]{EXPOSURE_ID});
            }
            if (sql.contains("SELECT id FROM rbvm.tenant")) {
                return initialized ? rows(new Object[]{TENANT_ID}) : rows();
            }
            if (sql.contains("FROM rbvm.case_audit_event e")) {
                return rows();
            }
            if (sql.contains("FROM rbvm.vulnerability_case") && sql.contains("FOR UPDATE")) {
                return rows(new Object[]{CASE_ID, "OPEN", 0L, null, null, null});
            }
            if (sql.contains("SELECT count(*) FROM rbvm.domain_materialization")) {
                return rows(new Object[]{1L});
            }
            if (sql.contains("FROM rbvm.postgres_projection_reconciliation")) {
                return rows(new Object[]{0L});
            }
            throw new AssertionError("Unexpected JDBC query:\n" + sql);
        }
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
            case "getLong" -> ((Number) values[cursor[0]][(Integer) arguments[0] - 1]).longValue();
            case "getInt" -> ((Number) values[cursor[0]][(Integer) arguments[0] - 1]).intValue();
            case "getBoolean" -> (Boolean) values[cursor[0]][(Integer) arguments[0] - 1];
            case "getTimestamp" -> {
                Object value = values[cursor[0]][(Integer) arguments[0] - 1];
                yield value instanceof Instant instant ? Timestamp.from(instant) : value;
            }
            case "close" -> null;
            default -> defaultValue(method.getReturnType());
        });
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler);
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == double.class) {
            return 0D;
        }
        if (type == float.class) {
            return 0F;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == char.class) {
            return '\0';
        }
        return null;
    }
}
