package io.rbvm.postgres;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

public final class PostgresMigrator {
    private static final long MIGRATION_LOCK = 7_445_826_186_421_901_337L;
    private static final List<Migration> MIGRATIONS = List.of(
            new Migration(1, "V1__canonical_rbvm.sql"),
            new Migration(2, "V2__dashboard_views.sql"),
            new Migration(3, "V3__case_workflow_audit.sql"),
            new Migration(4, "V4__postgres_projection_runtime.sql"),
            new Migration(5, "V5__postgres_read_catalog.sql"),
            new Migration(6, "V6__explicit_finding_lifecycle.sql"),
            new Migration(7, "V7__vulnerability_intelligence.sql"),
            new Migration(8, "V8__operational_analytics.sql"),
            new Migration(9, "V9__applicability_persistence.sql"),
            new Migration(10, "V10__cvss_v31_base_persistence.sql"),
            new Migration(11, "V11__cisa_kev_persistence.sql")
    );

    private final JdbcConnectionFactory connections;

    public PostgresMigrator(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    public int migrate() throws IOException {
        try (Connection connection = connections.open()) {
            verifyDatabase(connection.getMetaData());
            connection.setAutoCommit(true);
            advisoryLock(connection, true);
            try {
                bootstrapHistory(connection);
                int version = 0;
                for (Migration migration : MIGRATIONS) {
                    String script = resource(migration.fileName());
                    String checksum = sha256(script);
                    String installedChecksum = installedChecksum(connection, migration.version());
                    if (installedChecksum != null) {
                        if (!installedChecksum.equals(checksum)) {
                            throw new IOException(
                                    "Migration checksum mismatch for " + migration.fileName());
                        }
                    } else {
                        apply(connection, migration, script, checksum);
                    }
                    version = migration.version();
                }
                return version;
            } finally {
                advisoryLock(connection, false);
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("PostgreSQL migration failed", exception);
        }
    }

    public int installedVersion() throws IOException {
        try (Connection connection = connections.open();
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT COALESCE(max(version), 0) FROM rbvm.schema_migration")) {
            rows.next();
            return rows.getInt(1);
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not read PostgreSQL schema version",
                    exception
            );
        }
    }

    private static void verifyDatabase(DatabaseMetaData metadata) throws SQLException, IOException {
        if (!"PostgreSQL".equalsIgnoreCase(metadata.getDatabaseProductName())) {
            throw new IOException("RBVM PostgreSQL projection requires a PostgreSQL database");
        }
        if (metadata.getDatabaseMajorVersion() < 14) {
            throw new IOException("RBVM PostgreSQL projection requires PostgreSQL 14 or newer");
        }
    }

    private static void advisoryLock(Connection connection, boolean lock) throws SQLException {
        String function = lock ? "pg_advisory_lock" : "pg_advisory_unlock";
        try (PreparedStatement statement = connection.prepareStatement("SELECT " + function + "(?)")) {
            statement.setLong(1, MIGRATION_LOCK);
            statement.execute();
        }
    }

    private static void bootstrapHistory(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("CREATE SCHEMA IF NOT EXISTS rbvm");
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS rbvm.schema_migration (
                        version integer PRIMARY KEY CHECK (version > 0),
                        file_name text NOT NULL UNIQUE,
                        sha256 char(64) NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
                        installed_at timestamptz NOT NULL
                    )
                    """);
        }
    }

    private static String installedChecksum(Connection connection, int version) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT sha256 FROM rbvm.schema_migration WHERE version = ?")) {
            statement.setInt(1, version);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getString(1).trim() : null;
            }
        }
    }

    private static void apply(
            Connection connection,
            Migration migration,
            String script,
            String checksum
    ) throws SQLException {
        connection.setAutoCommit(false);
        try {
            try (Statement statement = connection.createStatement()) {
                for (String sql : SqlScriptParser.statements(script)) {
                    statement.execute(sql);
                }
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO rbvm.schema_migration(version, file_name, sha256, installed_at)
                    VALUES (?, ?, ?, ?)
                    """)) {
                statement.setInt(1, migration.version());
                statement.setString(2, migration.fileName());
                statement.setString(3, checksum);
                statement.setTimestamp(4, Timestamp.from(Instant.now()));
                statement.executeUpdate();
            }
            connection.commit();
        } catch (SQLException | RuntimeException exception) {
            connection.rollback();
            throw exception;
        } finally {
            connection.setAutoCommit(true);
        }
    }

    private static String resource(String fileName) throws IOException {
        String path = "/db/migration/" + fileName;
        try (InputStream input = PostgresMigrator.class.getResourceAsStream(path)) {
            if (input == null) {
                throw new IOException("Missing migration resource: " + path);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    private record Migration(int version, String fileName) {
    }
}
