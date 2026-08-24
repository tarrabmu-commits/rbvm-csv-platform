package io.rbvm.postgres;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Locale;

/** Diagnostic-only table and index statistics probe for scalability evidence. */
public final class PostgresFullScalabilityTableStatsProbe {
    private static final String BENCHMARK_MODE = "RBVM_SCALABILITY_BENCHMARK_MODE";

    private PostgresFullScalabilityTableStatsProbe() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: <outputTsv>");
        }
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        requireBenchmarkDatabase(settings);
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        StringBuilder tables = new StringBuilder(
                "relation\tseq_scan\tseq_tup_read\tidx_scan\tidx_tup_fetch\tn_tup_ins\tn_tup_upd\tn_tup_del\tn_live_tup\tn_dead_tup\n");
        StringBuilder indexes = new StringBuilder(
                "relation\tindex\tidx_scan\tidx_tup_read\tidx_tup_fetch\n");
        try (Connection connection = connections.open()) {
            try (PreparedStatement flush = connection.prepareStatement("SELECT pg_stat_force_next_flush()")) {
                flush.execute();
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT relname,
                           seq_scan, seq_tup_read, idx_scan, idx_tup_fetch,
                           n_tup_ins, n_tup_upd, n_tup_del, n_live_tup, n_dead_tup
                    FROM pg_stat_user_tables
                    WHERE schemaname = 'rbvm'
                    ORDER BY seq_tup_read DESC, idx_tup_fetch DESC, relname
                    """)) {
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        tables.append(rows.getString(1));
                        for (int column = 2; column <= 10; column++) {
                            tables.append('\t').append(rows.getLong(column));
                        }
                        tables.append('\n');
                    }
                }
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT relname, indexrelname, idx_scan, idx_tup_read, idx_tup_fetch
                    FROM pg_stat_user_indexes
                    WHERE schemaname = 'rbvm'
                    ORDER BY idx_tup_read DESC, idx_tup_fetch DESC, relname, indexrelname
                    """)) {
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        indexes.append(rows.getString(1)).append('\t')
                                .append(rows.getString(2)).append('\t')
                                .append(rows.getLong(3)).append('\t')
                                .append(rows.getLong(4)).append('\t')
                                .append(rows.getLong(5)).append('\n');
                    }
                }
            }
        }
        Path output = Path.of(args[0]);
        Path parent = output.toAbsolutePath().normalize().getParent();
        if (parent != null) Files.createDirectories(parent);
        Files.writeString(output, tables.toString(), StandardCharsets.UTF_8);
        Files.writeString(
                output.resolveSibling(output.getFileName().toString() + ".indexes.tsv"),
                indexes.toString(),
                StandardCharsets.UTF_8);
    }

    private static void requireBenchmarkDatabase(PostgresProjectionSettings settings) {
        if (!settings.enabled()) {
            throw new IllegalStateException("benchmark requires PostgreSQL projection settings");
        }
        if (!"true".equalsIgnoreCase(System.getenv(BENCHMARK_MODE))) {
            throw new IllegalStateException(BENCHMARK_MODE + "=true is required");
        }
        String jdbc = settings.jdbcUrl().toLowerCase(Locale.ROOT);
        if (!(jdbc.startsWith("jdbc:postgresql://127.0.0.1:")
                || jdbc.startsWith("jdbc:postgresql://localhost:"))) {
            throw new IllegalStateException("benchmark probe refuses non-local PostgreSQL targets");
        }
    }
}
