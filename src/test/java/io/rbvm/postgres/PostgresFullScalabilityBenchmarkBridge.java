package io.rbvm.postgres;

import io.rbvm.csv.AnalysisReport;
import io.rbvm.csv.ProjectionImport;
import io.rbvm.csv.Rfc4180CsvReader;
import io.rbvm.csv.WazuhCsvAnalyzer;
import io.rbvm.domain.CasePage;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.DomainMaterializationResult;
import io.rbvm.domain.InMemoryDomainCatalog;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Benchmark-only PostgreSQL bridge for the end-to-end CSV-first scalability harness.
 *
 * <p>This class is intentionally in the test tree. It seeds deterministic synthetic public
 * intelligence and therefore refuses to run unless benchmark mode is explicitly enabled and
 * the JDBC target is localhost. It must never be pointed at an operational RBVM database.</p>
 */
public final class PostgresFullScalabilityBenchmarkBridge {
    private static final String BENCHMARK_MODE = "RBVM_SCALABILITY_BENCHMARK_MODE";
    private static final int APPEND_BATCH = 1_000;
    private static final int READ_SAMPLE_LIMIT = 100;
    private static final String CISA_URI =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private static final String NVD_URI = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final String EPSS_URI = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
    private static final String CVE_PROGRAM_URI = "https://github.com/CVEProject/cvelistV5";
    private static final String CVSS4_VECTOR =
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";

    private PostgresFullScalabilityBenchmarkBridge() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            throw new IllegalArgumentException(
                    "usage: reset-schema | seed-export | project-manifest | priority-read ...");
        }
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        requireBenchmarkDatabase(settings);
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());

        switch (args[0]) {
            case "reset-schema" -> resetSchema(connections, requireArg(args, 1, "metricsJson"));
            case "seed-export" -> seedExport(
                    connections,
                    Path.of(requireArg(args, 1, "inputCsv")),
                    Path.of(requireArg(args, 2, "exportDirectory")),
                    Path.of(requireArg(args, 3, "metricsJson")),
                    requireArg(args, 4, "benchmarkId"));
            case "project-manifest" -> projectManifest(
                    connections,
                    Path.of(requireArg(args, 1, "inputCsv")),
                    Path.of(requireArg(args, 2, "manifestCsv")),
                    Path.of(requireArg(args, 3, "metricsJson")),
                    requireArg(args, 4, "sourceProfile"),
                    requireArg(args, 5, "benchmarkId"));
            case "priority-read" -> priorityRead(
                    connections,
                    Path.of(requireArg(args, 1, "priorityCsv")),
                    UUID.fromString(requireArg(args, 2, "importId")),
                    requireArg(args, 3, "sourceCsvSha256"),
                    Path.of(requireArg(args, 4, "metricsJson")),
                    requireArg(args, 5, "benchmarkId"));
            default -> throw new IllegalArgumentException("unknown benchmark bridge command: " + args[0]);
        }
    }

    private static void resetSchema(JdbcConnectionFactory connections, String metricsPath) throws Exception {
        long started = System.nanoTime();
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("DROP SCHEMA IF EXISTS rbvm CASCADE")) {
            statement.execute();
        }
        long elapsed = elapsedNanos(started);
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("contractId", "RBVM_FULL_SCALABILITY_POSTGRES_BRIDGE_V1");
        metrics.put("command", "reset-schema");
        metrics.put("resetSeconds", seconds(elapsed));
        writeJson(Path.of(metricsPath), metrics);
    }

    private static void seedExport(
            JdbcConnectionFactory connections,
            Path inputCsv,
            Path exportDirectory,
            Path metricsPath,
            String benchmarkId
    ) throws Exception {
        List<String> cves = readCves(inputCsv);
        if (cves.isEmpty()) throw new IOException("benchmark input contains no CVEs");
        PostgresPublicIntelligenceStore store = new PostgresPublicIntelligenceStore(connections, true);
        PostgresPublicIntelligenceSyncJobStore status =
                new PostgresPublicIntelligenceSyncJobStore(connections, false);
        PostgresCisaKevCatalogValidationReader cisaValidation =
                new PostgresCisaKevCatalogValidationReader(connections);

        DbStats beforeSeed = dbStats(connections);
        long seedStarted = System.nanoTime();
        SeedCounts counts = seedPublicIntelligence(store, status, cisaValidation, cves, benchmarkId);
        long seedNanos = elapsedNanos(seedStarted);
        DbStats afterSeed = dbStats(connections);

        PostgresCsvFirstLocalIntelligenceSnapshotExporter exporter =
                new PostgresCsvFirstLocalIntelligenceSnapshotExporter(store, status, cisaValidation);
        long exportStarted = System.nanoTime();
        var summary = exporter.export(inputCsv, exportDirectory);
        long exportNanos = elapsedNanos(exportStarted);
        DbStats afterExport = dbStats(connections);

        if (summary.uniqueCves() != cves.size()) {
            throw new IOException("local export unique-CVE count drifted");
        }
        if (summary.cvesWithoutActiveProviderRecords() != 0) {
            throw new IOException("benchmark local export unexpectedly lacks active provider records");
        }

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("contractId", "RBVM_FULL_SCALABILITY_POSTGRES_BRIDGE_V1");
        metrics.put("command", "seed-export");
        metrics.put("benchmarkId", benchmarkId);
        metrics.put("uniqueCves", cves.size());
        metrics.put("setupSeedSeconds", seconds(seedNanos));
        metrics.put("localLookupExportSeconds", seconds(exportNanos));
        metrics.put("localLookupCvesPerSecond", rate(cves.size(), exportNanos));
        metrics.put("seedRecords", counts.asMap());
        metrics.put("exportProviderRecords", summary.providerRecords());
        metrics.put("providersWithSuccessfulSnapshot", summary.providersWithSuccessfulSnapshot());
        metrics.put("dbSeedDelta", afterSeed.minus(beforeSeed).asMap());
        metrics.put("dbLookupExportDelta", afterExport.minus(afterSeed).asMap());
        metrics.put("exportBytes", directoryBytes(exportDirectory));
        writeJson(metricsPath, metrics);
    }

    private static SeedCounts seedPublicIntelligence(
            PostgresPublicIntelligenceStore store,
            PostgresPublicIntelligenceSyncJobStore status,
            PostgresCisaKevCatalogValidationReader cisaValidation,
            List<String> cves,
            String benchmarkId
    ) throws Exception {
        Instant observed = Instant.parse("2090-01-01T00:10:00Z");
        long nvd = seedProvider(
                store,
                PostgresPublicIntelligenceStore.Provider.NVD,
                NVD_URI,
                "synthetic-nvd-" + benchmarkId,
                cves,
                observed,
                (cve, index) -> nvdPayload(cve, index));
        long epss = seedProvider(
                store,
                PostgresPublicIntelligenceStore.Provider.FIRST_EPSS,
                EPSS_URI,
                "synthetic-epss-" + benchmarkId,
                cves,
                observed.plusSeconds(30),
                PostgresFullScalabilityBenchmarkBridge::epssPayload);
        long cveProgram = seedProvider(
                store,
                PostgresPublicIntelligenceStore.Provider.CVE_PROGRAM,
                CVE_PROGRAM_URI,
                "synthetic-cve-program-" + benchmarkId,
                cves,
                observed.plusSeconds(60),
                PostgresFullScalabilityBenchmarkBridge::cveProgramPayload);
        long cisa = seedCisa(
                store, status, cisaValidation, cves, benchmarkId, observed.plusSeconds(90));
        return new SeedCounts(nvd, epss, cisa, cveProgram);
    }

    private static long seedProvider(
            PostgresPublicIntelligenceStore store,
            PostgresPublicIntelligenceStore.Provider provider,
            String uri,
            String version,
            List<String> cves,
            Instant observed,
            PayloadFactory factory
    ) throws Exception {
        String sha = sha256(provider.name() + "|" + version + "|" + cves.size()
                + "|" + cves.get(0) + "|" + cves.get(cves.size() - 1));
        PostgresPublicIntelligenceStore.SourceDescriptor source =
                new PostgresPublicIntelligenceStore.SourceDescriptor(
                        provider, uri, version, sha, observed.minusSeconds(60), observed);
        var run = store.beginOrReplay(source, PostgresPublicIntelligenceStore.SyncMode.BOOTSTRAP,
                observed.minusSeconds(10));
        if (run.replayed()) {
            throw new IOException("benchmark source replayed unexpectedly for " + provider);
        }
        long records = 0;
        for (int offset = 0; offset < cves.size(); offset += APPEND_BATCH) {
            int end = Math.min(cves.size(), offset + APPEND_BATCH);
            List<PostgresPublicIntelligenceStore.RecordVersion> batch = new ArrayList<>(end - offset);
            for (int index = offset; index < end; index++) {
                String cve = cves.get(index);
                batch.add(new PostgresPublicIntelligenceStore.RecordVersion(
                        cve,
                        PostgresPublicIntelligenceStore.RecordState.ACTIVE,
                        observed.minusSeconds(30),
                        observed.minusSeconds(60),
                        factory.payload(cve, index),
                        observed));
            }
            var result = store.appendRecords(run.runId(), provider, batch);
            records += result.insertedRecords();
        }
        store.completeRun(run.runId(), provider, records, observed.plusSeconds(10));
        return records;
    }

    private static long seedCisa(
            PostgresPublicIntelligenceStore store,
            PostgresPublicIntelligenceSyncJobStore status,
            PostgresCisaKevCatalogValidationReader validation,
            List<String> cves,
            String benchmarkId,
            Instant observed
    ) throws Exception {
        List<String> listed = new ArrayList<>();
        for (int index = 0; index < cves.size(); index++) {
            if (index % 17 == 0) listed.add(cves.get(index));
        }
        String version = "synthetic-cisa-" + benchmarkId;
        String sha = sha256("CISA_KEV|" + version + "|" + cves.size() + "|" + listed.size());
        var source = new PostgresPublicIntelligenceStore.SourceDescriptor(
                PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                CISA_URI,
                version,
                sha,
                observed.minusSeconds(60),
                observed);
        var job = status.start(
                PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                PostgresPublicIntelligenceSyncJobStore.TriggerSource.SYSTEM,
                observed.minusSeconds(30));
        status.acquired(
                job.id(),
                PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                new PostgresPublicIntelligenceSyncJobStore.SourceIdentity(
                        source.sourceUri(), source.sourceVersion(), source.sourceSha256()),
                observed.minusSeconds(20));
        status.bundleBuilt(job.id(), PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                observed.minusSeconds(15));

        var run = store.beginOrReplay(source, PostgresPublicIntelligenceStore.SyncMode.BOOTSTRAP,
                observed.minusSeconds(10));
        if (run.replayed()) throw new IOException("benchmark CISA source replayed unexpectedly");
        long records = 0;
        for (int offset = 0; offset < listed.size(); offset += APPEND_BATCH) {
            int end = Math.min(listed.size(), offset + APPEND_BATCH);
            List<PostgresPublicIntelligenceStore.RecordVersion> batch = new ArrayList<>(end - offset);
            for (int index = offset; index < end; index++) {
                String cve = listed.get(index);
                batch.add(new PostgresPublicIntelligenceStore.RecordVersion(
                        cve,
                        PostgresPublicIntelligenceStore.RecordState.ACTIVE,
                        observed.minusSeconds(30),
                        observed.minusSeconds(60),
                        cisaPayload(cve),
                        observed));
            }
            records += store.appendRecords(
                    run.runId(), PostgresPublicIntelligenceStore.Provider.CISA_KEV, batch).insertedRecords();
        }
        store.completeRun(
                run.runId(), PostgresPublicIntelligenceStore.Provider.CISA_KEV, records,
                observed.plusSeconds(10));
        status.linkSyncRun(
                job.id(), PostgresPublicIntelligenceStore.Provider.CISA_KEV, run.runId(),
                observed.plusSeconds(12));
        status.complete(
                job.id(), PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                observed.plusSeconds(15));
        if (!validation.isCompleteValidatedCatalog(run.runId())) {
            throw new IOException("benchmark CISA run did not satisfy safe-negative validation contract");
        }
        return records;
    }

    private static void projectManifest(
            JdbcConnectionFactory connections,
            Path inputCsv,
            Path manifestCsv,
            Path metricsPath,
            String sourceProfile,
            String benchmarkId
    ) throws Exception {
        new PostgresMigrator(connections).migrate();
        DbStats before = dbStats(connections);
        UUID importId = UUID.randomUUID();
        AnalysisReport analysis = new WazuhCsvAnalyzer(sourceProfile).analyze(inputCsv, 0);
        InMemoryDomainCatalog local = new InMemoryDomainCatalog();
        DomainMaterializationResult localResult = local.materialize(importId, inputCsv, sourceProfile);
        PostgresCanonicalProjection projection = new PostgresCanonicalProjection(connections, false);

        long projectionStarted = System.nanoTime();
        projection.synchronizeImport(new ProjectionImport(
                importId, inputCsv, sourceProfile, analysis, localResult, Instant.now()));
        long projectionNanos = elapsedNanos(projectionStarted);
        DbStats afterProjection = dbStats(connections);

        PostgresCanonicalImportFindingExporter exporter =
                new PostgresCanonicalImportFindingExporter(connections);
        long manifestStarted = System.nanoTime();
        byte[] manifest = exporter.exportCsv(importId)
                .orElseThrow(() -> new IOException("canonical import Finding manifest is unavailable"));
        Files.createDirectories(manifestCsv.toAbsolutePath().normalize().getParent());
        Files.write(manifestCsv, manifest, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        long manifestNanos = elapsedNanos(manifestStarted);

        PostgresReadCatalog reads = new PostgresReadCatalog(connections);
        long readStarted = System.nanoTime();
        CasePage page = reads.queryCases(CaseQuery.firstPage(READ_SAMPLE_LIMIT));
        long readNanos = elapsedNanos(readStarted);
        DbStats afterRead = dbStats(connections);

        int manifestRows = csvDataRows(manifestCsv);
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("contractId", "RBVM_FULL_SCALABILITY_POSTGRES_BRIDGE_V1");
        metrics.put("command", "project-manifest");
        metrics.put("benchmarkId", benchmarkId);
        metrics.put("importId", importId.toString());
        metrics.put("sourceCsvSha256", analysis.fileSha256());
        metrics.put("logicalRows", analysis.logicalRows());
        metrics.put("acceptedRows", analysis.acceptedRows());
        metrics.put("canonicalProjectionSeconds", seconds(projectionNanos));
        metrics.put("canonicalProjectionRowsPerSecond", rate(analysis.logicalRows(), projectionNanos));
        metrics.put("manifestExportSeconds", seconds(manifestNanos));
        metrics.put("manifestRows", manifestRows);
        metrics.put("manifestBytes", Files.size(manifestCsv));
        metrics.put("firstPageReadSeconds", seconds(readNanos));
        metrics.put("firstPageLimit", READ_SAMPLE_LIMIT);
        metrics.put("firstPageCases", page.cases().size());
        metrics.put("dbProjectionDelta", afterProjection.minus(before).asMap());
        metrics.put("dbManifestAndReadDelta", afterRead.minus(afterProjection).asMap());
        writeJson(metricsPath, metrics);
    }

    private static void priorityRead(
            JdbcConnectionFactory connections,
            Path priorityCsv,
            UUID importId,
            String sourceCsvSha256,
            Path metricsPath,
            String benchmarkId
    ) throws Exception {
        new PostgresMigrator(connections).migrate();
        List<CanonicalMvpPriorityStore.PriorityRow> rows = readPriorityRows(priorityCsv);
        String prioritySha = sha256(Files.readAllBytes(priorityCsv));
        UUID csvRunId = UUID.randomUUID();
        UUID analysisId = UUID.randomUUID();
        CanonicalMvpPriorityStore store = new PostgresCanonicalMvpPriorityAccess(connections);
        DbStats before = dbStats(connections);

        long materializeStarted = System.nanoTime();
        var result = store.materialize(
                importId,
                csvRunId,
                analysisId,
                sourceCsvSha256,
                prioritySha,
                rows,
                Instant.now());
        long materializeNanos = elapsedNanos(materializeStarted);
        DbStats afterMaterialize = dbStats(connections);

        List<String> findingIds = findingPublicIds(connections, importId, READ_SAMPLE_LIMIT);
        long readStarted = System.nanoTime();
        int readResults = 0;
        for (String findingId : findingIds) {
            if (store.latestForFinding(findingId).isPresent()) readResults++;
        }
        long readNanos = elapsedNanos(readStarted);
        DbStats afterRead = dbStats(connections);

        if (result.mappedSourceRows() != rows.size()) {
            throw new IOException("canonical priority materialization did not map every source row");
        }
        if (readResults != findingIds.size()) {
            throw new IOException("sample canonical priority read lost materialized Finding results");
        }

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("contractId", "RBVM_FULL_SCALABILITY_POSTGRES_BRIDGE_V1");
        metrics.put("command", "priority-read");
        metrics.put("benchmarkId", benchmarkId);
        metrics.put("csvRunId", csvRunId.toString());
        metrics.put("analysisId", analysisId.toString());
        metrics.put("sourceRows", rows.size());
        metrics.put("canonicalFindings", result.canonicalFindings());
        metrics.put("insertedPriorityResults", result.insertedResults());
        metrics.put("priorityMaterializeSeconds", seconds(materializeNanos));
        metrics.put("priorityRowsPerSecond", rate(rows.size(), materializeNanos));
        metrics.put("prioritySampleReadSeconds", seconds(readNanos));
        metrics.put("prioritySampleReadCount", readResults);
        metrics.put("priorityCsvSha256", prioritySha);
        metrics.put("dbPriorityMaterializeDelta", afterMaterialize.minus(before).asMap());
        metrics.put("dbPriorityReadDelta", afterRead.minus(afterMaterialize).asMap());
        writeJson(metricsPath, metrics);
    }

    private static List<CanonicalMvpPriorityStore.PriorityRow> readPriorityRows(Path path) throws Exception {
        List<CanonicalMvpPriorityStore.PriorityRow> output = new ArrayList<>();
        try (Reader raw = Files.newBufferedReader(path, StandardCharsets.UTF_8);
             Rfc4180CsvReader reader = new Rfc4180CsvReader(raw)) {
            List<String> header = reader.readRow();
            if (header == null) throw new IOException("priority CSV is empty");
            Map<String, Integer> columns = columns(header);
            String[] required = {
                    "RBVM_MVP_Priority_Status", "RBVM_MVP_Priority_Front",
                    "RBVM_MVP_Priority_Dominated_By", "RBVM_MVP_Priority_Dominates",
                    "RBVM_MVP_Priority_Blockers", "RBVM_MVP_Priority_Explanation",
                    "RBVM_MVP_Priority_Method_SHA256", "KEV_Listed", "Internet_Facing",
                    "Asset_Criticality", "EPSS_Probability", "CVSS4_Context_Score"
            };
            for (String name : required) {
                if (!columns.containsKey(name)) throw new IOException("priority CSV missing " + name);
            }
            List<String> row;
            long sourceRow = 2;
            while ((row = reader.readRow()) != null) {
                String methodSha = value(row, columns, "RBVM_MVP_Priority_Method_SHA256");
                if (!CanonicalMvpPriorityStore.METHOD_SHA256.equals(methodSha)) {
                    throw new IOException("priority method SHA drift at source row " + sourceRow);
                }
                output.add(new CanonicalMvpPriorityStore.PriorityRow(
                        sourceRow,
                        value(row, columns, "RBVM_MVP_Priority_Status"),
                        nullableInteger(value(row, columns, "RBVM_MVP_Priority_Front")),
                        nullableLong(value(row, columns, "RBVM_MVP_Priority_Dominated_By")),
                        nullableLong(value(row, columns, "RBVM_MVP_Priority_Dominates")),
                        value(row, columns, "RBVM_MVP_Priority_Blockers"),
                        value(row, columns, "RBVM_MVP_Priority_Explanation"),
                        methodSha,
                        nullableBoolean(value(row, columns, "KEV_Listed")),
                        value(row, columns, "Internet_Facing"),
                        value(row, columns, "Asset_Criticality"),
                        nullableDecimal(value(row, columns, "EPSS_Probability")),
                        nullableDecimal(value(row, columns, "CVSS4_Context_Score"))));
                sourceRow++;
            }
        }
        return output;
    }

    private static List<String> findingPublicIds(
            JdbcConnectionFactory connections,
            UUID importId,
            int limit
    ) throws Exception {
        List<String> result = new ArrayList<>();
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT DISTINCT e.public_id
                     FROM rbvm.import_observation io
                     JOIN rbvm.exposure_observation eo
                       ON eo.tenant_id = io.tenant_id AND eo.observation_id = io.observation_id
                     JOIN rbvm.exposure e
                       ON e.tenant_id = eo.tenant_id AND e.id = eo.exposure_id
                     WHERE io.import_id = ?
                     ORDER BY e.public_id
                     LIMIT ?
                     """)) {
            statement.setObject(1, importId);
            statement.setInt(2, limit);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) result.add(rows.getString(1));
            }
        }
        return result;
    }

    private static List<String> readCves(Path inputCsv) throws IOException {
        Set<String> unique = new LinkedHashSet<>();
        try (Reader raw = Files.newBufferedReader(inputCsv, StandardCharsets.UTF_8);
             Rfc4180CsvReader reader = new Rfc4180CsvReader(raw)) {
            List<String> header = reader.readRow();
            if (header == null) throw new IOException("benchmark CSV is empty");
            Map<String, Integer> columns = columns(header);
            Integer cveColumn = columns.get("CVE_ID");
            if (cveColumn == null) throw new IOException("benchmark CSV has no CVE_ID column");
            List<String> row;
            while ((row = reader.readRow()) != null) {
                if (cveColumn >= row.size()) throw new IOException("benchmark row is missing CVE_ID");
                String cve = row.get(cveColumn).trim().toUpperCase(Locale.ROOT);
                if (!cve.matches("^CVE-[0-9]{4}-[0-9]{4,}$")) {
                    throw new IOException("invalid benchmark CVE: " + cve);
                }
                unique.add(cve);
            }
        }
        return unique.stream().sorted().toList();
    }

    private static String nvdPayload(String cve, int index) {
        return "{"
                + "\"id\":\"" + cve + "\","
                + "\"published\":\"2089-01-01T00:00:00.000\","
                + "\"lastModified\":\"2089-12-31T00:00:00.000\","
                + "\"vulnStatus\":\"Analyzed\","
                + "\"sourceIdentifier\":\"rbvm-capacity-benchmark@nvd.synthetic\","
                + "\"descriptions\":[{\"lang\":\"en\",\"value\":\"Synthetic capacity record "
                + cve + "\"}],"
                + "\"weaknesses\":[],\"references\":[],\"configurations\":[],"
                + "\"metrics\":{\"cvssMetricV40\":[{"
                + "\"source\":\"rbvm-capacity-benchmark@nvd.synthetic\","
                + "\"type\":\"Primary\",\"cvssData\":{"
                + "\"version\":\"4.0\",\"vectorString\":\"" + CVSS4_VECTOR + "\","
                + "\"baseScore\":10.0,\"baseSeverity\":\"CRITICAL\"}}]}}";
    }

    private static String epssPayload(String cve, int index) {
        BigDecimal probability = BigDecimal.valueOf((index % 999) + 1)
                .divide(BigDecimal.valueOf(1000));
        BigDecimal percentile = probability.add(new BigDecimal("0.0005")).min(new BigDecimal("0.999999"));
        return "{\"cve\":\"" + cve + "\",\"epss\":\"" + probability.toPlainString()
                + "\",\"percentile\":\"" + percentile.toPlainString()
                + "\",\"scoreDate\":\"2090-01-01\"}";
    }

    private static String cisaPayload(String cve) {
        return "{\"cveID\":\"" + cve
                + "\",\"dateAdded\":\"2089-12-01\",\"dueDate\":\"2090-01-15\","
                + "\"vendorProject\":\"Synthetic\",\"product\":\"Capacity Benchmark\","
                + "\"vulnerabilityName\":\"Synthetic benchmark record\","
                + "\"requiredAction\":\"Benchmark only\","
                + "\"knownRansomwareCampaignUse\":\"Unknown\",\"notes\":\"\"}";
    }

    private static String cveProgramPayload(String cve, int index) {
        return "{\"dataType\":\"CVE_RECORD\",\"dataVersion\":\"5.1\","
                + "\"cveMetadata\":{\"cveId\":\"" + cve + "\",\"state\":\"PUBLISHED\"},"
                + "\"containers\":{\"cna\":{\"providerMetadata\":{\"orgId\":\"benchmark\"},"
                + "\"descriptions\":[],\"affected\":[],\"references\":[],\"metrics\":[]}}}";
    }

    private static DbStats dbStats(JdbcConnectionFactory connections) throws Exception {
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

    private static int csvDataRows(Path path) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            int lines = 0;
            while (reader.readLine() != null) lines++;
            return Math.max(0, lines - 1);
        }
    }

    private static long directoryBytes(Path directory) throws IOException {
        try (var paths = Files.walk(directory)) {
            long total = 0;
            for (Path path : paths.filter(Files::isRegularFile).toList()) total += Files.size(path);
            return total;
        }
    }

    private static Map<String, Integer> columns(List<String> header) throws IOException {
        Map<String, Integer> output = new LinkedHashMap<>();
        for (int index = 0; index < header.size(); index++) {
            String name = index == 0 && header.get(index).startsWith("\uFEFF")
                    ? header.get(index).substring(1) : header.get(index);
            if (output.putIfAbsent(name, index) != null) {
                throw new IOException("duplicate CSV header: " + name);
            }
        }
        return output;
    }

    private static String value(List<String> row, Map<String, Integer> columns, String name) {
        int index = Objects.requireNonNull(columns.get(name), name);
        return index < row.size() ? row.get(index).trim() : "";
    }

    private static Integer nullableInteger(String value) {
        return value.isBlank() ? null : Integer.valueOf(value);
    }

    private static Long nullableLong(String value) {
        return value.isBlank() ? null : Long.valueOf(value);
    }

    private static BigDecimal nullableDecimal(String value) {
        return value.isBlank() ? null : new BigDecimal(value);
    }

    private static Boolean nullableBoolean(String value) {
        if (value.isBlank()) return null;
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "true", "1", "yes", "listed" -> true;
            case "false", "0", "no", "not_listed", "not listed" -> false;
            default -> throw new IllegalArgumentException("invalid boolean: " + value);
        };
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
            throw new IllegalStateException("benchmark bridge refuses non-local PostgreSQL targets");
        }
    }

    private static String requireArg(String[] args, int index, String name) {
        if (index >= args.length || args[index].isBlank()) {
            throw new IllegalArgumentException("missing argument: " + name);
        }
        return args[index];
    }

    private static long elapsedNanos(long started) {
        return System.nanoTime() - started;
    }

    private static double seconds(long nanos) {
        return Math.round((nanos / 1_000_000_000.0) * 1000.0) / 1000.0;
    }

    private static double rate(long units, long nanos) {
        if (nanos <= 0) return 0.0;
        return Math.round((units / (nanos / 1_000_000_000.0)) * 10.0) / 10.0;
    }

    private static String sha256(String value) {
        return sha256(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
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
                output.append(json(String.valueOf(entry.getKey()))).append(':').append(json(entry.getValue()));
            }
            return output.append('}').toString();
        }
        if (value instanceof Iterable<?> iterable) {
            StringBuilder output = new StringBuilder("[");
            boolean first = true;
            for (Object item : iterable) {
                if (!first) output.append(',');
                first = false;
                output.append(json(item));
            }
            return output.append(']').toString();
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

    @FunctionalInterface
    private interface PayloadFactory {
        String payload(String cve, int index);
    }

    private record SeedCounts(long nvd, long epss, long cisaKev, long cveProgram) {
        Map<String, Object> asMap() {
            Map<String, Object> output = new LinkedHashMap<>();
            output.put("NVD", nvd);
            output.put("FIRST_EPSS", epss);
            output.put("CISA_KEV", cisaKev);
            output.put("CVE_PROGRAM", cveProgram);
            return output;
        }
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
