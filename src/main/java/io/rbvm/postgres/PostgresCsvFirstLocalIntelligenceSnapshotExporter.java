package io.rbvm.postgres;

import io.rbvm.csv.CsvFirstLocalIntelligenceSnapshotExporter;
import io.rbvm.csv.Rfc4180CsvReader;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * PostgreSQL-backed implementation of the CSV-first local public-intelligence export boundary.
 *
 * <p>The export is deliberately limited to CVEs present in the uploaded CSV. V30 current-state
 * lookup resolves tombstones before ACTIVE filtering, so this class never resurrects older
 * provider state. Provider status is exported separately so consumers can distinguish a true
 * CISA KEV non-membership result from a provider that has never completed a validated snapshot.</p>
 */
public final class PostgresCsvFirstLocalIntelligenceSnapshotExporter
        implements CsvFirstLocalIntelligenceSnapshotExporter {
    private static final int LOOKUP_BATCH_SIZE = 1_000;
    private static final Pattern CVE = Pattern.compile("^CVE-[0-9]{4}-[0-9]{4,}$");
    private static final Base64.Encoder BASE64 = Base64.getEncoder();

    private final PostgresPublicIntelligenceStore intelligence;
    private final PublicIntelligenceStatusReader status;
    private final CisaKevCatalogValidationReader cisaCatalogValidation;

    public PostgresCsvFirstLocalIntelligenceSnapshotExporter(
            PostgresPublicIntelligenceStore intelligence,
            PublicIntelligenceStatusReader status,
            CisaKevCatalogValidationReader cisaCatalogValidation
    ) {
        this.intelligence = Objects.requireNonNull(intelligence, "intelligence");
        this.status = Objects.requireNonNull(status, "status");
        this.cisaCatalogValidation = Objects.requireNonNull(
                cisaCatalogValidation, "cisaCatalogValidation");
    }

    @Override
    public ExportSummary export(Path inputCsv, Path outputDirectory) throws IOException {
        Objects.requireNonNull(inputCsv, "inputCsv");
        Objects.requireNonNull(outputDirectory, "outputDirectory");
        List<String> cves = readCves(inputCsv);
        prepareOutput(outputDirectory);

        Map<PostgresPublicIntelligenceStore.Provider, PublicIntelligenceStatusReader.ProviderStatus>
                providerStatus = new EnumMap<>(PostgresPublicIntelligenceStore.Provider.class);
        for (PublicIntelligenceStatusReader.ProviderStatus value : status.readStatus()) {
            providerStatus.put(value.provider(), value);
        }

        long providersWithSuccess = writeProviderStatus(outputDirectory, providerStatus);
        writeRequestedCves(outputDirectory, cves);

        long providerRecords = 0;
        long cvesWithoutRecords = 0;
        Path recordsPath = outputDirectory.resolve("records.tsv");
        try (BufferedWriter writer = Files.newBufferedWriter(
                recordsPath,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE
        )) {
            writer.write("CVE_ID\tProvider\tPayload_Base64\tRecord_SHA256\tSource_Modified_At\t"
                    + "Source_Published_At\tRecord_Observed_At\tSync_Run_ID\tSync_Mode\t"
                    + "Source_URI\tSource_Version\tSource_SHA256\tRun_Observed_At\tRun_Completed_At\n");
            for (int offset = 0; offset < cves.size(); offset += LOOKUP_BATCH_SIZE) {
                int end = Math.min(cves.size(), offset + LOOKUP_BATCH_SIZE);
                Set<String> batch = new LinkedHashSet<>(cves.subList(offset, end));
                Map<String, Map<PostgresPublicIntelligenceStore.Provider,
                        PostgresPublicIntelligenceStore.CurrentRecord>> current =
                        intelligence.lookupCurrent(batch);
                for (String cve : cves.subList(offset, end)) {
                    Map<PostgresPublicIntelligenceStore.Provider,
                            PostgresPublicIntelligenceStore.CurrentRecord> records = current.get(cve);
                    if (records == null || records.isEmpty()) {
                        cvesWithoutRecords++;
                        continue;
                    }
                    for (PostgresPublicIntelligenceStore.Provider provider
                            : PostgresPublicIntelligenceStore.Provider.values()) {
                        PostgresPublicIntelligenceStore.CurrentRecord record = records.get(provider);
                        if (record == null) continue;
                        writeRecord(writer, record);
                        providerRecords++;
                    }
                }
            }
        }

        ExportSummary summary = new ExportSummary(
                cves.size(), providerRecords, cvesWithoutRecords, providersWithSuccess);
        writeManifest(outputDirectory, summary);
        return summary;
    }

    private static List<String> readCves(Path inputCsv) throws IOException {
        if (!Files.isRegularFile(inputCsv) || Files.isSymbolicLink(inputCsv)) {
            throw new IOException("CSV-first local intelligence input must be a regular file");
        }
        Set<String> unique = new LinkedHashSet<>();
        try (Reader raw = Files.newBufferedReader(inputCsv, StandardCharsets.UTF_8);
             Rfc4180CsvReader csv = new Rfc4180CsvReader(raw)) {
            List<String> header = csv.readRow();
            if (header == null) throw new IOException("CSV-first local intelligence input is empty");
            List<String> normalizedHeader = new ArrayList<>(header);
            if (!normalizedHeader.isEmpty()) {
                normalizedHeader.set(0, stripBom(normalizedHeader.get(0)));
            }
            int cveColumn = normalizedHeader.indexOf("CVE_ID");
            if (cveColumn < 0) throw new IOException("input CSV must contain a CVE_ID header");
            if (normalizedHeader.lastIndexOf("CVE_ID") != cveColumn) {
                throw new IOException("input CSV contains duplicate CVE_ID headers");
            }
            List<String> row;
            while ((row = csv.readRow()) != null) {
                if (cveColumn >= row.size()) throw new IOException("CSV row is missing CVE_ID column");
                String cve = row.get(cveColumn).trim().toUpperCase();
                if (!CVE.matcher(cve).matches()) {
                    throw new IOException("invalid CVE_ID in CSV-first local intelligence input: " + cve);
                }
                unique.add(cve);
            }
        }
        return unique.stream().sorted().toList();
    }

    private static void prepareOutput(Path outputDirectory) throws IOException {
        if (Files.isSymbolicLink(outputDirectory)) {
            throw new IOException("local intelligence export directory must not be a symbolic link");
        }
        if (Files.exists(outputDirectory)) {
            if (!Files.isDirectory(outputDirectory)) {
                throw new IOException("local intelligence export path must be a directory");
            }
            try (var entries = Files.list(outputDirectory)) {
                if (entries.findAny().isPresent()) {
                    throw new IOException("local intelligence export directory must be empty");
                }
            }
        } else {
            Files.createDirectories(outputDirectory);
        }
    }

    private long writeProviderStatus(
            Path outputDirectory,
            Map<PostgresPublicIntelligenceStore.Provider,
                    PublicIntelligenceStatusReader.ProviderStatus> status
    ) throws IOException {
        long successful = 0;
        Path path = outputDirectory.resolve("provider-status.tsv");
        try (BufferedWriter writer = Files.newBufferedWriter(
                path, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            writer.write("Provider\tHas_Success\tSafe_Negative_Absence\tSuccess_ID\tSync_Mode\tSource_URI\t"
                    + "Source_Version\tSource_SHA256\tSource_Published_At\tObserved_At\tCompleted_At\t"
                    + "Record_Count\n");
            for (PostgresPublicIntelligenceStore.Provider provider
                    : PostgresPublicIntelligenceStore.Provider.values()) {
                PublicIntelligenceStatusReader.ProviderStatus value = status.get(provider);
                boolean hasSuccess = value != null && value.latestSuccessId() != null;
                boolean safeNegativeAbsence = provider == PostgresPublicIntelligenceStore.Provider.CISA_KEV
                        && hasSuccess
                        && cisaCatalogValidation.isCompleteValidatedCatalog(value.latestSuccessId());
                if (hasSuccess) successful++;
                writer.write(provider.name());
                writer.write('\t');
                writer.write(Boolean.toString(hasSuccess));
                writer.write('\t');
                writer.write(Boolean.toString(safeNegativeAbsence));
                writer.write('\t');
                writer.write(tsv(hasSuccess ? value.latestSuccessId().toString() : null));
                writer.write('\t');
                writer.write(tsv(hasSuccess ? value.latestSuccessMode() : null));
                writer.write('\t');
                writer.write(tsv(hasSuccess ? value.latestSuccessSourceUri() : null));
                writer.write('\t');
                writer.write(tsv(hasSuccess ? value.latestSuccessSourceVersion() : null));
                writer.write('\t');
                writer.write(tsv(hasSuccess ? value.latestSuccessSourceSha256() : null));
                writer.write('\t');
                writer.write(tsv(hasSuccess ? instant(value.latestSuccessSourcePublishedAt()) : null));
                writer.write('\t');
                writer.write(tsv(hasSuccess ? instant(value.latestSuccessObservedAt()) : null));
                writer.write('\t');
                writer.write(tsv(hasSuccess ? instant(value.latestSuccessCompletedAt()) : null));
                writer.write('\t');
                writer.write(hasSuccess && value.latestSuccessRecordCount() != null
                        ? Long.toString(value.latestSuccessRecordCount()) : "");
                writer.write('\n');
            }
        }
        return successful;
    }

    private static void writeRequestedCves(Path outputDirectory, List<String> cves) throws IOException {
        Path path = outputDirectory.resolve("requested-cves.txt");
        Files.writeString(
                path,
                cves.isEmpty() ? "" : String.join("\n", cves) + "\n",
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE
        );
    }

    private static void writeRecord(
            BufferedWriter writer,
            PostgresPublicIntelligenceStore.CurrentRecord record
    ) throws IOException {
        writer.write(record.cveId());
        writer.write('\t');
        writer.write(record.provider().name());
        writer.write('\t');
        writer.write(BASE64.encodeToString(record.payloadJson().getBytes(StandardCharsets.UTF_8)));
        writer.write('\t');
        writer.write(record.recordSha256());
        writer.write('\t');
        writer.write(tsv(instant(record.sourceModifiedAt())));
        writer.write('\t');
        writer.write(tsv(instant(record.sourcePublishedAt())));
        writer.write('\t');
        writer.write(tsv(instant(record.recordObservedAt())));
        writer.write('\t');
        writer.write(record.syncRunId().toString());
        writer.write('\t');
        writer.write(record.syncMode().name());
        writer.write('\t');
        writer.write(tsv(record.sourceUri()));
        writer.write('\t');
        writer.write(tsv(record.sourceVersion()));
        writer.write('\t');
        writer.write(record.sourceSha256());
        writer.write('\t');
        writer.write(tsv(instant(record.runObservedAt())));
        writer.write('\t');
        writer.write(tsv(instant(record.runCompletedAt())));
        writer.write('\n');
    }

    private static void writeManifest(Path outputDirectory, ExportSummary summary) throws IOException {
        String value = "contractId=" + CONTRACT_ID + "\n"
                + "uniqueCves=" + summary.uniqueCves() + "\n"
                + "providerRecords=" + summary.providerRecords() + "\n"
                + "cvesWithoutActiveProviderRecords=" + summary.cvesWithoutActiveProviderRecords() + "\n"
                + "providersWithSuccessfulSnapshot=" + summary.providersWithSuccessfulSnapshot() + "\n";
        Files.writeString(
                outputDirectory.resolve("export.properties"),
                value,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE
        );
    }

    private static String stripBom(String value) {
        return value != null && value.startsWith("\uFEFF") ? value.substring(1) : value;
    }

    private static String instant(Instant value) {
        return value == null ? null : value.toString();
    }

    private static String tsv(String value) throws IOException {
        if (value == null) return "";
        if (value.indexOf('\t') >= 0 || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            throw new IOException("local intelligence export metadata must be single-line TSV-safe text");
        }
        return value;
    }
}
