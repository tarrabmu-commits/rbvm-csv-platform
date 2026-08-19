package io.rbvm.postgres;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.math.BigDecimal;
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

public final class PostgresCvssV31ImporterSelfTest {
    private static final Instant NOW = Instant.parse("2026-08-19T08:10:00Z");
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID VULN_A = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static final UUID VULN_B = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private static final String CVE_A = "CVE-2026-10001";
    private static final String CVE_B = "CVE-2026-10002";
    private static final String FOREIGN_CVE = "CVE-2026-19999";
    private static final String SOURCE_A = "https://nvd.nist.gov/vuln/detail/" + CVE_A;
    private static final String SOURCE_B = "https://nvd.nist.gov/vuln/detail/" + CVE_B;
    private static final String VENDOR_SOURCE = "https://security.example.test/advisories/" + CVE_A;

    private PostgresCvssV31ImporterSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        importsHistoryReplaysIdempotentlyAndKeepsSourcesIndependent();
        System.out.println("PostgresCvssV31ImporterSelfTest: PASS");
    }

    private static void importsHistoryReplaysIdempotentlyAndKeepsSourcesIndependent() throws Exception {
        Path first = Files.createTempFile("cvss-v31-import-", ".csv");
        Path conflict = Files.createTempFile("cvss-v31-conflict-", ".csv");
        Path alternateSource = Files.createTempFile("cvss-v31-alternate-source-", ".csv");
        try {
            String vectorA = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
            String vectorB = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
            Files.writeString(first, headers()
                    + CVE_A + ",3.1,9.8," + vectorA + "," + SOURCE_A + ",2026-08-18T10:00:00Z\r\n"
                    + CVE_A + ",3.1,9.8," + vectorA + "," + SOURCE_A + ",2026-08-18T10:00:00Z\r\n"
                    + CVE_B + ",3.1,7.5," + vectorB + "," + SOURCE_B + ",2026-08-18T11:00:00Z\r\n"
                    + FOREIGN_CVE + ",3.1,7.5," + vectorB
                    + ",https://nvd.nist.gov/vuln/detail/" + FOREIGN_CVE
                    + ",2026-08-18T12:00:00Z\r\n",
                    StandardCharsets.UTF_8);

            Files.writeString(conflict, headers()
                    + CVE_A + ",3.1,7.5," + vectorB + "," + SOURCE_A
                    + ",2026-08-18T10:00:00Z\r\n",
                    StandardCharsets.UTF_8);

            // Same CVE and timestamp, but a different source. Metrics are intentionally reordered;
            // persistence must store the canonical Base metric order and must not arbitrate sources.
            String reordered = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N";
            Files.writeString(alternateSource, headers()
                    + CVE_A + ",3.1,9.8," + reordered + "," + VENDOR_SOURCE
                    + ",2026-08-18T10:00:00Z\r\n",
                    StandardCharsets.UTF_8);

            FakeDatabase database = new FakeDatabase();
            database.vulnerabilities.put(CVE_A, VULN_A);
            database.vulnerabilities.put(CVE_B, VULN_B);
            PostgresCvssV31Importer importer = new PostgresCvssV31Importer(
                    database::connection,
                    false,
                    Clock.fixed(NOW, ZoneOffset.UTC)
            );

            CvssV31ImportResult firstResult = importer.importFile(first);
            assert importer.schemaVersion() == 10;
            assert firstResult.analysis().logicalRows() == 4;
            assert firstResult.analysis().deduplicatedRows() == 1;
            assert firstResult.analysis().acceptedRows() == 3;
            assert firstResult.insertedEvidence() == 2;
            assert firstResult.replayedEvidence() == 0;
            assert firstResult.persistenceQuarantinedRows() == 1;
            assert firstResult.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals("CVE_NOT_FOUND_IN_TENANT"));
            assert database.evidence.size() == 2;
            assert database.catalogRevision == 1;

            CvssV31ImportResult replay = importer.importFile(first);
            assert replay.insertedEvidence() == 0;
            assert replay.replayedEvidence() == 2;
            assert replay.persistenceQuarantinedRows() == 1;
            assert database.evidence.size() == 2;
            assert database.catalogRevision == 1 : "pure replay must not change catalog revision";

            CvssV31ImportResult conflicting = importer.importFile(conflict);
            assert conflicting.insertedEvidence() == 0;
            assert conflicting.replayedEvidence() == 0;
            assert conflicting.persistenceQuarantinedRows() == 1;
            assert conflicting.persistenceIssues().stream()
                    .anyMatch(issue -> issue.code().equals(
                            "CONFLICTING_PERSISTED_CVSS_EVIDENCE_TIMESTAMP"));
            assert database.evidence.size() == 2;
            assert database.catalogRevision == 1;

            CvssV31ImportResult alternate = importer.importFile(alternateSource);
            assert alternate.insertedEvidence() == 1;
            assert alternate.replayedEvidence() == 0;
            assert alternate.persistenceQuarantinedRows() == 0;
            assert database.evidence.size() == 3;
            assert database.catalogRevision == 2;
            StoredEvidence vendor = database.evidence.get(key(
                    VULN_A,
                    VENDOR_SOURCE,
                    Instant.parse("2026-08-18T10:00:00Z")
            ));
            assert vendor != null;
            assert vendor.vector.equals(vectorA) : vendor.vector;
            assert vendor.score.compareTo(new BigDecimal("9.8")) == 0;

            assert database.commits == 4;
            assert database.rollbacks == 0;
            assert database.serializableTransactions == 4;
        } finally {
            Files.deleteIfExists(first);
            Files.deleteIfExists(conflict);
            Files.deleteIfExists(alternateSource);
        }
    }

    private static String headers() {
        return "CVE_ID,CVSS_Version,CVSS_Base_Score,CVSS_Vector,CVSS_Source,CVSS_Observed_At\r\n";
    }

    private static final class FakeDatabase {
        private final Map<String, UUID> vulnerabilities = new HashMap<>();
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
                case "executeQuery" -> rows(new Object[]{10});
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
            if (sql.contains("JOIN rbvm.exposure")) {
                UUID tenant = (UUID) parameters.get(1);
                String cve = (String) parameters.get(2);
                UUID vulnerability = tenant.equals(TENANT_ID) ? vulnerabilities.get(cve) : null;
                return vulnerability == null ? rows() : rows(new Object[]{vulnerability});
            }
            if (sql.contains("FROM rbvm.cvss_v31_base_evidence")) {
                UUID vulnerability = (UUID) parameters.get(2);
                String source = (String) parameters.get(3);
                Instant observedAt = ((Timestamp) parameters.get(4)).toInstant();
                StoredEvidence stored = evidence.get(key(vulnerability, source, observedAt));
                return stored == null ? rows() : rows(new Object[]{stored.sha256});
            }
            throw new AssertionError("Unexpected query:\n" + sql);
        }

        private int update(String sql, Map<Integer, Object> parameters) {
            if (sql.contains("INSERT INTO rbvm.cvss_v31_base_evidence")) {
                UUID vulnerability = (UUID) parameters.get(3);
                BigDecimal score = (BigDecimal) parameters.get(5);
                String vector = (String) parameters.get(6);
                String source = (String) parameters.get(7);
                Instant observedAt = ((Timestamp) parameters.get(8)).toInstant();
                String sha256 = (String) parameters.get(10);
                String key = key(vulnerability, source, observedAt);
                if (evidence.putIfAbsent(key, new StoredEvidence(score, vector, sha256)) != null) {
                    throw new AssertionError("Importer attempted duplicate CVSS evidence insert");
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

    private record StoredEvidence(BigDecimal score, String vector, String sha256) {
    }

    private static String key(UUID vulnerability, String source, Instant observedAt) {
        return vulnerability + "|" + source + "|" + observedAt;
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
