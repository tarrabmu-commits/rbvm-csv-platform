package io.rbvm.postgres;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class PostgresMigratorSelfTest {
    private PostgresMigratorSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        appliesAndReplaysVersionedMigrations();
        rejectsChecksumDrift();
        rollsBackFailedMigration();
        System.out.println("PostgresMigratorSelfTest: PASS");
    }

    private static void appliesAndReplaysVersionedMigrations() throws Exception {
        FakeDatabase database = new FakeDatabase();
        PostgresMigrator migrator = new PostgresMigrator(database::connection);
        assert migrator.migrate() == 5;
        assert database.checksums.size() == 5;
        assert database.commits == 5;
        assert database.rollbacks == 0;
        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE TABLE rbvm.observation"));
        long observationCreates = database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.observation (")).count();

        assert migrator.migrate() == 5;
        assert database.commits == 5 : "replay must not reapply migrations";
        assert database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.observation (")).count()
                == observationCreates;
        assert database.advisoryLocks == 2;
        assert database.advisoryUnlocks == 2;
    }

    private static void rejectsChecksumDrift() throws Exception {
        FakeDatabase database = new FakeDatabase();
        PostgresMigrator migrator = new PostgresMigrator(database::connection);
        migrator.migrate();
        database.checksums.put(2, "0".repeat(64));
        boolean rejected = false;
        try {
            migrator.migrate();
        } catch (IOException expected) {
            rejected = expected.getMessage().contains("checksum mismatch");
        }
        assert rejected;
    }

    private static void rollsBackFailedMigration() {
        FakeDatabase database = new FakeDatabase();
        database.failWhenSqlContains = "CREATE TABLE rbvm.asset (";
        PostgresMigrator migrator = new PostgresMigrator(database::connection);
        boolean failed = false;
        try {
            migrator.migrate();
        } catch (IOException expected) {
            failed = expected.getMessage().contains("migration failed");
        }
        assert failed;
        assert database.rollbacks == 1;
        assert database.commits == 0;
        assert database.checksums.isEmpty();
    }

    private static final class FakeDatabase {
        private final Map<Integer, String> checksums = new HashMap<>();
        private final List<String> executedSql = new ArrayList<>();
        private int commits;
        private int rollbacks;
        private int advisoryLocks;
        private int advisoryUnlocks;
        private String failWhenSqlContains;

        private Connection connection() {
            return proxy(Connection.class, this::connectionCall);
        }

        private Object connectionCall(Object proxy, Method method, Object[] arguments)
                throws SQLException {
            return switch (method.getName()) {
                case "getMetaData" -> metadata();
                case "prepareStatement" -> prepared((String) arguments[0]);
                case "createStatement" -> statement();
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
                case "unwrap" -> null;
                case "isWrapperFor" -> false;
                default -> defaultValue(method.getReturnType());
            };
        }

        private DatabaseMetaData metadata() {
            return proxy(DatabaseMetaData.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "getDatabaseProductName" -> "PostgreSQL";
                case "getDatabaseMajorVersion" -> 18;
                default -> defaultValue(method.getReturnType());
            });
        }

        private Statement statement() {
            return proxy(Statement.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "execute" -> {
                    String sql = (String) arguments[0];
                    if (failWhenSqlContains != null && sql.contains(failWhenSqlContains)) {
                        throw new SQLException("synthetic migration failure");
                    }
                    executedSql.add(sql);
                    yield false;
                }
                case "executeQuery" -> resultSet(
                        checksums.isEmpty()
                                ? List.of(0)
                                : List.of(checksums.keySet().stream().mapToInt(Integer::intValue)
                                        .max().orElse(0))
                );
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
                    case "execute" -> {
                        String normalized = sql.toLowerCase(Locale.ROOT);
                        if (normalized.contains("pg_advisory_lock")) {
                            advisoryLocks++;
                        } else if (normalized.contains("pg_advisory_unlock")) {
                            advisoryUnlocks++;
                        }
                        yield false;
                    }
                    case "executeQuery" -> {
                        if (sql.contains("SELECT sha256")) {
                            String checksum = checksums.get((Integer) parameters.get(1));
                            yield resultSet(checksum == null ? List.of() : List.of(checksum));
                        }
                        yield resultSet(List.of());
                    }
                    case "executeUpdate" -> {
                        if (sql.contains("INSERT INTO rbvm.schema_migration")) {
                            checksums.put((Integer) parameters.get(1), (String) parameters.get(3));
                        }
                        yield 1;
                    }
                    case "close" -> null;
                    default -> defaultValue(method.getReturnType());
                };
            });
        }

        private static ResultSet resultSet(List<?> values) {
            int[] cursor = {-1};
            return proxy(ResultSet.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "next" -> ++cursor[0] < values.size();
                case "getString" -> values.get(cursor[0]).toString();
                case "getInt" -> ((Number) values.get(cursor[0])).intValue();
                case "getLong" -> ((Number) values.get(cursor[0])).longValue();
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
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == float.class) {
            return 0F;
        }
        if (type == double.class) {
            return 0D;
        }
        if (type == char.class) {
            return '\0';
        }
        return null;
    }
}
