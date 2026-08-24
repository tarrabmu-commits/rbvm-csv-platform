package io.rbvm.postgres;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Imports one validated PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1 into the V30 global store.
 *
 * <p>The bundle is validated in full before a PostgreSQL STAGING run is opened. Records are
 * then replay/inserted in bounded batches and the run becomes COMPLETE only after exact record
 * accounting. A bundle created by this process never changes tenant evidence, RBVM priority,
 * Formula results, SLA, or customer context.</p>
 */
public final class PublicIntelligenceSyncBundleImporter {
    private static final String ARTIFACT_TYPE = "PUBLIC_INTELLIGENCE_SYNC_BUNDLE";
    private static final String SCHEMA_VERSION = "1";
    private static final int BATCH_SIZE = 1_000;
    private static final int MAX_LINE_CHARS = 32 * 1024 * 1024;
    private static final Pattern SHA256_PATTERN = Pattern.compile("^[a-f0-9]{64}$");
    private static final List<String> HEADER = List.of(
            "CVE_ID",
            "Record_State",
            "Source_Modified_At",
            "Source_Published_At",
            "Observed_At",
            "Payload_Base64"
    );
    private static final Set<String> MANIFEST_KEYS = Set.of(
            "artifactType",
            "schemaVersion",
            "provider",
            "syncMode",
            "sourceUri",
            "sourceVersion",
            "sourceSha256",
            "sourcePublishedAt",
            "observedAt",
            "startedAt",
            "recordCount",
            "recordsSha256"
    );

    private PublicIntelligenceSyncBundleImporter() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException(
                    "Usage: PublicIntelligenceSyncBundleImporter <bundle-directory>");
        }
        Path bundleDirectory = Path.of(args[0]).toAbsolutePath().normalize();
        ValidatedBundle bundle = validateBundle(bundleDirectory);

        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(
                System.getenv());
        if (!settings.enabled()) {
            throw new IllegalArgumentException(
                    "Set RBVM_PROJECTION_BACKEND=POSTGRESQL before importing public intelligence");
        }
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        PostgresPublicIntelligenceStore store = new PostgresPublicIntelligenceStore(
                connections, settings.migrate());

        ImportSummary result = importBundle(store, bundle);
        System.out.printf(
                Locale.ROOT,
                "provider=%s run_id=%s status=%s inserted=%d replayed=%d records=%d%n",
                bundle.provider(),
                result.runId(),
                result.status(),
                result.inserted(),
                result.replayed(),
                result.recordCount());
    }

    static ImportSummary importBundle(
            PostgresPublicIntelligenceStore store,
            ValidatedBundle bundle
    ) throws IOException {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(bundle, "bundle");
        PostgresPublicIntelligenceStore.SourceDescriptor descriptor =
                new PostgresPublicIntelligenceStore.SourceDescriptor(
                        bundle.provider(),
                        bundle.sourceUri(),
                        bundle.sourceVersion(),
                        bundle.sourceSha256(),
                        bundle.sourcePublishedAt(),
                        bundle.observedAt());

        PostgresPublicIntelligenceStore.BeginResult begin = store.beginOrReplay(
                descriptor, bundle.syncMode(), bundle.startedAt());
        if (begin.replayed()
                && begin.status() == PostgresPublicIntelligenceStore.SyncStatus.COMPLETE) {
            return new ImportSummary(
                    begin.runId(), "REPLAYED_COMPLETE", 0, bundle.recordCount(), bundle.recordCount());
        }

        long inserted = 0;
        long replayed = 0;
        boolean ownsRun = !begin.replayed();
        try {
            List<PostgresPublicIntelligenceStore.RecordVersion> batch = new ArrayList<>(BATCH_SIZE);
            try (BufferedReader reader = utf8Reader(bundle.recordsPath())) {
                requireHeader(reader.readLine());
                String line;
                long lineNumber = 1;
                while ((line = reader.readLine()) != null) {
                    lineNumber++;
                    requireBoundedLine(line, lineNumber);
                    batch.add(parseRecord(line, lineNumber));
                    if (batch.size() == BATCH_SIZE) {
                        PostgresPublicIntelligenceStore.AppendResult append = store.appendRecords(
                                begin.runId(), bundle.provider(), batch);
                        inserted += append.insertedRecords();
                        replayed += append.replayedRecords();
                        batch.clear();
                    }
                }
                if (!batch.isEmpty()) {
                    PostgresPublicIntelligenceStore.AppendResult append = store.appendRecords(
                            begin.runId(), bundle.provider(), batch);
                    inserted += append.insertedRecords();
                    replayed += append.replayedRecords();
                }
            }
            PostgresPublicIntelligenceStore.CompletionResult completion = store.completeRun(
                    begin.runId(), bundle.provider(), bundle.recordCount(), Instant.now());
            return new ImportSummary(
                    begin.runId(),
                    completion.replayed() ? "REPLAYED_COMPLETE" : "COMPLETE",
                    inserted,
                    replayed,
                    completion.recordCount());
        } catch (IOException | RuntimeException exception) {
            if (ownsRun) {
                try {
                    store.failRun(
                            begin.runId(),
                            bundle.provider(),
                            "BUNDLE_IMPORT_FAILED",
                            safeFailureDetail(exception),
                            Instant.now());
                } catch (IOException | RuntimeException failureTransition) {
                    exception.addSuppressed(failureTransition);
                }
            }
            throw exception;
        }
    }

    static ValidatedBundle validateBundle(Path bundleDirectory) throws IOException {
        Objects.requireNonNull(bundleDirectory, "bundleDirectory");
        if (!Files.isDirectory(bundleDirectory, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(bundleDirectory)) {
            throw new IOException("public-intelligence bundle must be a non-symlink directory");
        }
        Path manifestPath = bundleDirectory.resolve("manifest.properties");
        Path recordsPath = bundleDirectory.resolve("records.tsv");
        requireRegularFile(manifestPath, "manifest.properties");
        requireRegularFile(recordsPath, "records.tsv");

        Properties properties = new Properties();
        try (Reader reader = utf8Reader(manifestPath)) {
            properties.load(reader);
        }
        if (!properties.stringPropertyNames().equals(MANIFEST_KEYS)) {
            throw new IOException("manifest.properties has missing or unknown keys");
        }
        requireEquals(ARTIFACT_TYPE, property(properties, "artifactType"), "artifactType");
        requireEquals(SCHEMA_VERSION, property(properties, "schemaVersion"), "schemaVersion");

        PostgresPublicIntelligenceStore.Provider provider = parseProvider(
                property(properties, "provider"));
        PostgresPublicIntelligenceStore.SyncMode syncMode = parseSyncMode(
                property(properties, "syncMode"));
        String sourceUri = property(properties, "sourceUri");
        if (!sourceUri.startsWith("https://")) {
            throw new IOException("manifest sourceUri must use https");
        }
        String sourceVersion = property(properties, "sourceVersion");
        String sourceSha256 = requireSha256(property(properties, "sourceSha256"), "sourceSha256");
        Instant sourcePublishedAt = nullableInstant(
                properties.getProperty("sourcePublishedAt"), "sourcePublishedAt");
        Instant observedAt = requiredInstant(property(properties, "observedAt"), "observedAt");
        Instant startedAt = requiredInstant(property(properties, "startedAt"), "startedAt");
        if (startedAt.isAfter(observedAt)) {
            throw new IOException("manifest startedAt must not be after observedAt");
        }
        long recordCount = parseNonNegativeLong(property(properties, "recordCount"), "recordCount");
        String recordsSha256 = requireSha256(
                property(properties, "recordsSha256"), "recordsSha256");
        String actualRecordsSha256 = sha256(recordsPath);
        if (!recordsSha256.equals(actualRecordsSha256)) {
            throw new IOException("records.tsv SHA-256 does not match manifest");
        }

        long actualCount = validateRecords(recordsPath);
        if (actualCount != recordCount) {
            throw new IOException(
                    "records.tsv contains " + actualCount + " records but manifest declares "
                            + recordCount);
        }

        return new ValidatedBundle(
                bundleDirectory,
                recordsPath,
                provider,
                syncMode,
                sourceUri,
                sourceVersion,
                sourceSha256,
                sourcePublishedAt,
                observedAt,
                startedAt,
                recordCount,
                recordsSha256);
    }

    private static long validateRecords(Path recordsPath) throws IOException {
        Set<String> cves = new HashSet<>();
        long count = 0;
        try (BufferedReader reader = utf8Reader(recordsPath)) {
            requireHeader(reader.readLine());
            String line;
            long lineNumber = 1;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                requireBoundedLine(line, lineNumber);
                PostgresPublicIntelligenceStore.RecordVersion record = parseRecord(line, lineNumber);
                if (!cves.add(record.cveId())) {
                    throw new IOException(
                            "records.tsv contains duplicate CVE at line " + lineNumber + ": "
                                    + record.cveId());
                }
                count++;
            }
        }
        return count;
    }

    private static PostgresPublicIntelligenceStore.RecordVersion parseRecord(
            String line,
            long lineNumber
    ) throws IOException {
        String[] cells = line.split("\\t", -1);
        if (cells.length != HEADER.size()) {
            throw new IOException(
                    "records.tsv line " + lineNumber + " must contain exactly "
                            + HEADER.size() + " columns");
        }
        PostgresPublicIntelligenceStore.RecordState state;
        try {
            state = PostgresPublicIntelligenceStore.RecordState.valueOf(cells[1]);
        } catch (IllegalArgumentException exception) {
            throw new IOException(
                    "records.tsv line " + lineNumber + " has invalid Record_State", exception);
        }
        String payloadJson = decodePayload(cells[5], state, lineNumber);
        try {
            return new PostgresPublicIntelligenceStore.RecordVersion(
                    cells[0],
                    state,
                    nullableInstant(cells[2], "Source_Modified_At line " + lineNumber),
                    nullableInstant(cells[3], "Source_Published_At line " + lineNumber),
                    payloadJson,
                    requiredInstant(cells[4], "Observed_At line " + lineNumber));
        } catch (IllegalArgumentException exception) {
            throw new IOException(
                    "records.tsv line " + lineNumber + " violates the V30 record contract",
                    exception);
        }
    }

    private static String decodePayload(
            String encoded,
            PostgresPublicIntelligenceStore.RecordState state,
            long lineNumber
    ) throws IOException {
        if (state == PostgresPublicIntelligenceStore.RecordState.TOMBSTONE) {
            if (!encoded.isEmpty()) {
                throw new IOException(
                        "records.tsv line " + lineNumber + " TOMBSTONE must not carry payload");
            }
            return null;
        }
        if (encoded.isEmpty()) {
            throw new IOException(
                    "records.tsv line " + lineNumber + " ACTIVE must carry payload");
        }
        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException exception) {
            throw new IOException(
                    "records.tsv line " + lineNumber + " payload is not valid Base64", exception);
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(payload))
                    .toString();
        } catch (CharacterCodingException exception) {
            throw new IOException(
                    "records.tsv line " + lineNumber + " payload is not valid UTF-8", exception);
        }
    }

    private static void requireHeader(String line) throws IOException {
        if (line == null) throw new IOException("records.tsv is empty");
        requireBoundedLine(line, 1);
        List<String> actual = List.of(line.split("\\t", -1));
        if (!HEADER.equals(actual)) {
            throw new IOException("records.tsv header does not match PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1");
        }
    }

    private static void requireBoundedLine(String line, long lineNumber) throws IOException {
        if (line.length() > MAX_LINE_CHARS) {
            throw new IOException("records.tsv line " + lineNumber + " exceeds maximum size");
        }
    }

    private static BufferedReader utf8Reader(Path path) throws IOException {
        return new BufferedReader(new InputStreamReader(
                Files.newInputStream(path),
                StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)));
    }

    private static void requireRegularFile(Path path, String name) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
            throw new IOException(name + " must be a regular non-symlink file");
        }
    }

    private static String property(Properties properties, String key) throws IOException {
        String value = properties.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IOException("manifest property " + key + " is required");
        }
        return value.trim();
    }

    private static void requireEquals(String expected, String actual, String field) throws IOException {
        if (!expected.equals(actual)) {
            throw new IOException("manifest " + field + " must equal " + expected);
        }
    }

    private static String requireSha256(String value, String field) throws IOException {
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if (!SHA256_PATTERN.matcher(normalized).matches()) {
            throw new IOException(field + " must be lowercase SHA-256 hex");
        }
        return normalized;
    }

    private static Instant requiredInstant(String value, String field) throws IOException {
        Instant result = nullableInstant(value, field);
        if (result == null) throw new IOException(field + " is required");
        return result;
    }

    private static Instant nullableInstant(String value, String field) throws IOException {
        if (value == null || value.isBlank()) return null;
        try {
            return Instant.parse(value.trim());
        } catch (DateTimeParseException exception) {
            throw new IOException(field + " must be an ISO-8601 UTC instant", exception);
        }
    }

    private static long parseNonNegativeLong(String value, String field) throws IOException {
        try {
            long parsed = Long.parseLong(value);
            if (parsed < 0) throw new NumberFormatException("negative");
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IOException(field + " must be a non-negative integer", exception);
        }
    }

    private static PostgresPublicIntelligenceStore.Provider parseProvider(String value)
            throws IOException {
        try {
            return PostgresPublicIntelligenceStore.Provider.valueOf(value);
        } catch (IllegalArgumentException exception) {
            throw new IOException("manifest provider is unsupported", exception);
        }
    }

    private static PostgresPublicIntelligenceStore.SyncMode parseSyncMode(String value)
            throws IOException {
        try {
            return PostgresPublicIntelligenceStore.SyncMode.valueOf(value);
        } catch (IllegalArgumentException exception) {
            throw new IOException("manifest syncMode is unsupported", exception);
        }
    }

    private static String sha256(Path path) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
        try (DigestInputStream stream = new DigestInputStream(Files.newInputStream(path), digest)) {
            byte[] buffer = new byte[64 * 1024];
            while (stream.read(buffer) != -1) {
                // DigestInputStream updates the digest as bytes are read.
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static String safeFailureDetail(Throwable throwable) {
        String text = throwable.getClass().getSimpleName();
        if (throwable.getMessage() != null && !throwable.getMessage().isBlank()) {
            text += ": " + throwable.getMessage().replace('\n', ' ').replace('\r', ' ');
        }
        return text.length() <= 512 ? text : text.substring(0, 512);
    }

    record ValidatedBundle(
            Path bundleDirectory,
            Path recordsPath,
            PostgresPublicIntelligenceStore.Provider provider,
            PostgresPublicIntelligenceStore.SyncMode syncMode,
            String sourceUri,
            String sourceVersion,
            String sourceSha256,
            Instant sourcePublishedAt,
            Instant observedAt,
            Instant startedAt,
            long recordCount,
            String recordsSha256
    ) {
        ValidatedBundle {
            Objects.requireNonNull(bundleDirectory, "bundleDirectory");
            Objects.requireNonNull(recordsPath, "recordsPath");
            Objects.requireNonNull(provider, "provider");
            Objects.requireNonNull(syncMode, "syncMode");
            Objects.requireNonNull(sourceUri, "sourceUri");
            Objects.requireNonNull(sourceVersion, "sourceVersion");
            Objects.requireNonNull(sourceSha256, "sourceSha256");
            Objects.requireNonNull(observedAt, "observedAt");
            Objects.requireNonNull(startedAt, "startedAt");
            Objects.requireNonNull(recordsSha256, "recordsSha256");
        }
    }

    record ImportSummary(
            java.util.UUID runId,
            String status,
            long inserted,
            long replayed,
            long recordCount
    ) {
        ImportSummary {
            Objects.requireNonNull(runId, "runId");
            Objects.requireNonNull(status, "status");
            if (inserted < 0 || replayed < 0 || recordCount < 0) {
                throw new IllegalArgumentException("import counts must be non-negative");
            }
        }
    }
}
