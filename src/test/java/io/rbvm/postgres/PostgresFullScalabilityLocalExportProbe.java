package io.rbvm.postgres;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Benchmark-only isolated process for measuring the CSV-first V30 local lookup/export hot path.
 *
 * <p>Public-intelligence seeding is deliberately performed by a different process so this probe's
 * process RSS/CPU/wall metrics describe lookup/export rather than benchmark fixture construction.</p>
 */
public final class PostgresFullScalabilityLocalExportProbe {
    private static final String BENCHMARK_MODE = "RBVM_SCALABILITY_BENCHMARK_MODE";

    private PostgresFullScalabilityLocalExportProbe() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new IllegalArgumentException("usage: <inputCsv> <exportDirectory> <metricsJson>");
        }
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        requireBenchmarkDatabase(settings);
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        PostgresPublicIntelligenceStore store = new PostgresPublicIntelligenceStore(connections, false);
        PostgresPublicIntelligenceSyncJobStore status =
                new PostgresPublicIntelligenceSyncJobStore(connections, false);
        PostgresCisaKevCatalogValidationReader cisaValidation =
                new PostgresCisaKevCatalogValidationReader(connections);
        PostgresCsvFirstLocalIntelligenceSnapshotExporter exporter =
                new PostgresCsvFirstLocalIntelligenceSnapshotExporter(store, status, cisaValidation);

        Path inputCsv = Path.of(args[0]);
        Path exportDirectory = Path.of(args[1]);
        Path metricsPath = Path.of(args[2]);
        DbStats before = stats(connections);
        long started = System.nanoTime();
        var summary = exporter.export(inputCsv, exportDirectory);
        long elapsed = System.nanoTime() - started;
        DbStats after = stats(connections);

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("contractId", "RBVM_FULL_SCALABILITY_LOCAL_EXPORT_PROBE_V1");
        metrics.put("uniqueCves", summary.uniqueCves());
        metrics.put("providerRecords", summary.providerRecords());
        metrics.put("cvesWithoutActiveProviderRecords", summary.cvesWithoutActiveProviderRecords());
        metrics.put("providersWithSuccessfulSnapshot", summary.providersWithSuccessfulSnapshot());
        metrics.put("localLookupExportSeconds", seconds(elapsed));
        metrics.put("localLookupCvesPerSecond", rate(summary.uniqueCves(), elapsed));
        metrics.put("exportBytes", directoryBytes(exportDirectory));
        metrics.put("dbLookupExportDelta", after.minus(before).asMap());
        writeJson(metricsPath, metrics);
    }

    private static DbStats stats(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT xact_commit, xact_rollback, blks_read, blks_hit,
                            tup_returned, tup_fetched, tup_inserted, tup_updated, tup_deleted,
                            temp_files, temp_bytes
                     FROM pg_stat_database
                     WHERE datname = current_database()
                     """)) {
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) return DbStats.zero();
                return new DbStats(
                        rows.getLong(1), rows.getLong(2), rows.getLong(3), rows.getLong(4),
                        rows.getLong(5), rows.getLong(6), rows.getLong(7), rows.getLong(8),
                        rows.getLong(9), rows.getLong(10), rows.getLong(11));
            }
        }
    }

    private static long directoryBytes(Path directory) throws IOException {
        try (var paths = Files.walk(directory)) {
            long total = 0;
            for (Path path : paths.filter(Files::isRegularFile).toList()) total += Files.size(path);
            return total;
        }
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

    private static double seconds(long nanos) {
        return Math.round((nanos / 1_000_000_000.0) * 1000.0) / 1000.0;
    }

    private static double rate(long units, long nanos) {
        if (nanos <= 0) return 0.0;
        return Math.round((units / (nanos / 1_000_000_000.0)) * 10.0) / 10.0;
    }

    private static void writeJson(Path path, Map<String, Object> value) throws IOException {
        Path parent = path.toAbsolutePath().normalize().getParent();
        if (parent != null) Files.createDirectories(parent);
        Files.writeString(
                path,
                json(value) + "\n",
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
    }

    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof String text) return '"' + escape(text) + '"';
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?, ?> map) {
            StringBuilder output = new StringBuilder("{");
            boolean first = true;
            for (var entry : map.entrySet()) {
                if (!first) output.append(',');
                first = false;
                output.append(json(String.valueOf(entry.getKey())))
                        .append(':').append(json(entry.getValue()));
            }
            return output.append('}').toString();
        }
        return json(value.toString());
    }

    private static String escape(String value) {
        StringBuilder output = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            switch (c) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> {
                    if (c < 0x20) output.append(String.format("\\u%04x", (int) c));
                    else output.append(c);
                }
            }
        }
        return output.toString();
    }

    private record DbStats(
            long xactCommit,
            long xactRollback,
            long blocksRead,
            long blocksHit,
            long tuplesReturned,
            long tuplesFetched,
            long tuplesInserted,
            long tuplesUpdated,
            long tuplesDeleted,
            long tempFiles,
            long tempBytes
    ) {
        static DbStats zero() {
            return new DbStats(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }

        DbStats minus(DbStats before) {
            return new DbStats(
                    xactCommit - before.xactCommit,
                    xactRollback - before.xactRollback,
                    blocksRead - before.blocksRead,
                    blocksHit - before.blocksHit,
                    tuplesReturned - before.tuplesReturned,
                    tuplesFetched - before.tuplesFetched,
                    tuplesInserted - before.tuplesInserted,
                    tuplesUpdated - before.tuplesUpdated,
                    tuplesDeleted - before.tuplesDeleted,
                    tempFiles - before.tempFiles,
                    tempBytes - before.tempBytes);
        }

        Map<String, Object> asMap() {
            Map<String, Object> output = new LinkedHashMap<>();
            output.put("xactCommit", xactCommit);
            output.put("xactRollback", xactRollback);
            output.put("blocksRead", blocksRead);
            output.put("blocksHit", blocksHit);
            output.put("tuplesReturned", tuplesReturned);
            output.put("tuplesFetched", tuplesFetched);
            output.put("tuplesInserted", tuplesInserted);
            output.put("tuplesUpdated", tuplesUpdated);
            output.put("tuplesDeleted", tuplesDeleted);
            output.put("tempFiles", tempFiles);
            output.put("tempBytes", tempBytes);
            return output;
        }
    }
}
