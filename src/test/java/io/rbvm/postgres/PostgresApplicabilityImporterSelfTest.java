package io.rbvm.postgres;

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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class PostgresApplicabilityImporterSelfTest {
    private static final Instant NOW = Instant.parse("2026-08-19T07:00:00Z");
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID FINDING_A = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID FINDING_B = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID FOREIGN_FINDING = UUID.fromString("33333333-3333-4333-8333-333333333333");

    private PostgresApplicabilityImporterSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        importsHistoryReplaysIdempotentlyAndQuarantinesUnsafeRows();
        System.out.println("PostgresApplicabilityImporterSelfTest: PASS");
    }

    private static void importsHistoryReplaysIdempotentlyAndQuarantinesUnsafeRows() throws Exception {
        Path first = Files.createTempFile("applicability-import-", ".csv");
        Path conflict = Files.createTempFile("applicability-conflict-", ".csv");
        try {
            Files.writeString(first, headers()
                    + FINDING_A + ",APPLICABLE,Installed component and vulnerable feature are present,Vendor advisory,2026-08-18T10:00:00Z\r\n"
                    + FINDING_A + ",APPLICABLE,Installed component and vulnerable feature are present,Vendor advisory,2026-08-18T10:00:00Z\r\n"
                    + FINDING_B + ",UNKNOWN,Configuration evidence is inconclusive,Internal review,2026-08-18T11:00:00Z\r\n"
                    + FOREIGN_FINDING + ",NOT_APPLICABLE,Foreign tenant evidence,Vendor advisory,2026-08-18T12:00:00Z\r\n",
                    StandardCharsets.UTF_8);

            Files.writeString(conflict, headers()
                    + FINDING_A + ",NOT_APPLICABLE,Different conclusion,Second review,2026-08-18T10:00:00Z\r\n",
                    StandardCharsets.UTF_8);

            FakeDatabase database = new FakeDatabase();
            database.findings.add(FINDING_A);
            database.findings.add(FINDING_B);
            PostgresApplicabilityImporter importer = new PostgresApplicabilityImporter(
                    database::connection,
                    false,
                    Clock.fixed(NOW, ZoneOffset.UTC)
            );

            ApplicabilityImportResult firstResult = importer.importFile(first);
            assert importer.schemaVersion() == 9;
            assert firstResult.analysis().logicalRows() == 4;
            assert firstResult.analysis().deduplicatedRows() == 1;
            assert firstResult.analysis().acceptedRows() == 3;
            assert firstResult.insertedAssessments() == 2;
            assert firstResult.replayedAssessments() == 0;
            assert firstResult.persistenceQuarantinedRows() == 1;
            assert firstResult.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals("FINDING_NOT_FOUND"));
            assert database.assessments.size() == 2;
            assert database.catalogRevision == 1;

            ApplicabilityImportResult replay = importer.importFile(first);
            assert replay.insertedAssessments() == 0;
            assert replay.replayedAssessments() == 2;
            assert replay.persistenceQuarantinedRows() == 1;
            assert database.assessments.size() == 2;
            assert database.catalogRevision == 1 : "pure replay must not change catalog revision";

            ApplicabilityImportResult conflicting = importer.importFile(conflict);
            assert conflicting.insertedAssessments() == 0;
            assert conflicting.replayedAssessments() == 0;
            assert conflicting.persistenceQuarantinedRows() == 1;
            assert conflicting.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals(
                            "CONFLICTING_PERSISTED_ASSESSMENT_TIMESTAMP"));
            assert database.assessments.size() == 2;
            assert database.commits == 3;
            assert database.rollbacks == 0;
            assert database.serializableTransactions == 3;
        } finally {
            Files.deleteIfExists(first);
            Files.deleteIfExists(conflict);
        }
    }

    private static String headers() {
        return "Finding_ID,Applicability_Status,Applicability_Reason,Evidence_Source,Evaluated_At\r\n";
    }

    private static final class FakeDatabase {
        private final Set<UUID> findings = new HashSet<>();
        private final Map<String, String> assessments = new HashMap<>();
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
                case "executeQuery" -> rows(new Object[]{9});
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
            if (sql.contains("FROM rbvm.exposure")) {
                UUID tenant = (UUID) parameters.get(1);
                UUID finding = (UUID) parameters.get(2);
                return tenant.equals(TENANT_ID) && findings.contains(finding)
                        ? rows(new Object[]{1}) : rows();
            }
            if (sql.contains("SELECT evidence_sha256")) {
                UUID finding = (UUID) parameters.get(2);
                Instant evaluatedAt = ((Timestamp) parameters.get(3)).toInstant();
                String hash = assessments.get(key(finding, evaluatedAt));
                return hash == null ? rows() : rows(new Object[]{hash});
            }
            throw new AssertionError("Unexpected query:\n" + sql);
        }

        private int update(String sql, Map<Integer, Object> parameters) {
            if (sql.contains("INSERT INTO rbvm.applicability_assessment")) {
                UUID finding = (UUID) parameters.get(3);
                Instant evaluatedAt = ((Timestamp) parameters.get(7)).toInstant();
                String hash = (String) parameters.get(9);
                String key = key(finding, evaluatedAt);
                if (assessments.putIfAbsent(key, hash) != null) {
                    throw new AssertionError("Importer attempted duplicate assessment insert");
                }
                return 1;
            }
            if (sql.contains("UPDATE rbvm.catalog_state")) {
                catalogRevision++;
                return 1;
            }
            throw new AssertionError("Unexpected update:\n" + sql);
        }

        private static String key(UUID finding, Instant evaluatedAt) {
            return finding + "|" + evaluatedAt;
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
