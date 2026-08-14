package io.rbvm.csv;

import io.rbvm.domain.CatalogSnapshot;
import io.rbvm.domain.CaseActionCommand;
import io.rbvm.domain.CaseAuditEvent;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.DomainCatalog;
import io.rbvm.domain.DomainMaterializationResult;
import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.domain.PreparedCaseAction;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * Application service for the local CSV vertical slice.
 *
 * <p>The service stores raw evidence and a metadata envelope on disk. It keeps
 * a reconstructable local command model for validation and recovery; the read
 * catalog may be local or PostgreSQL.</p>
 */
public final class CsvImportService implements AutoCloseable {
    private static final String LOCAL_TENANT = "local";
    private static final String LOCAL_ACTOR = "local-operator";
    private static final String LOCAL_ACTOR_ASSURANCE = "UNAUTHENTICATED_LOCAL";
    private static final int PREVIEW_LIMIT = 20;

    private final Path importsDirectory;
    private final Path stagingDirectory;
    private final Path workflowEventsDirectory;
    private final long maximumUploadBytes;
    private final Clock clock;
    private final DomainCatalog domainCatalog;
    private final DomainCatalog readCatalog;
    private final CanonicalProjection canonicalProjection;
    private final Map<UUID, StoredImport> imports = new ConcurrentHashMap<>();
    private final Map<UUID, DomainMaterializationResult> materializations = new ConcurrentHashMap<>();
    private final Map<String, UUID> createIdempotency = new ConcurrentHashMap<>();
    private final Map<String, UUID> fileIdentity = new ConcurrentHashMap<>();
    private final List<String> recoveryWarnings = new ArrayList<>();
    private final Object mutationLock = new Object();
    private long nextWorkflowSequence = 1;

    public CsvImportService(Path dataDirectory, long maximumUploadBytes) throws IOException {
        this(
                dataDirectory,
                maximumUploadBytes,
                Clock.systemUTC(),
                new InMemoryDomainCatalog(),
                new NoopCanonicalProjection()
        );
    }

    public CsvImportService(
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection
    ) throws IOException {
        this(
                dataDirectory,
                maximumUploadBytes,
                Clock.systemUTC(),
                new InMemoryDomainCatalog(),
                canonicalProjection
        );
    }

    CsvImportService(Path dataDirectory, long maximumUploadBytes, Clock clock) throws IOException {
        this(
                dataDirectory,
                maximumUploadBytes,
                clock,
                new InMemoryDomainCatalog(),
                new NoopCanonicalProjection()
        );
    }

    CsvImportService(
            Path dataDirectory,
            long maximumUploadBytes,
            Clock clock,
            DomainCatalog domainCatalog
    ) throws IOException {
        this(
                dataDirectory,
                maximumUploadBytes,
                clock,
                domainCatalog,
                new NoopCanonicalProjection()
        );
    }

    CsvImportService(
            Path dataDirectory,
            long maximumUploadBytes,
            Clock clock,
            DomainCatalog domainCatalog,
            CanonicalProjection canonicalProjection
    ) throws IOException {
        this(dataDirectory, maximumUploadBytes, clock, domainCatalog, domainCatalog,
                canonicalProjection);
    }

    CsvImportService(
            Path dataDirectory,
            long maximumUploadBytes,
            Clock clock,
            DomainCatalog domainCatalog,
            DomainCatalog readCatalog,
            CanonicalProjection canonicalProjection
    ) throws IOException {
        Objects.requireNonNull(dataDirectory, "dataDirectory");
        if (maximumUploadBytes < 1) {
            throw new IllegalArgumentException("maximumUploadBytes must be positive");
        }
        this.maximumUploadBytes = maximumUploadBytes;
        this.clock = Objects.requireNonNull(clock, "clock");
        this.domainCatalog = Objects.requireNonNull(domainCatalog, "domainCatalog");
        this.readCatalog = Objects.requireNonNull(readCatalog, "readCatalog");
        this.canonicalProjection = Objects.requireNonNull(
                canonicalProjection,
                "canonicalProjection"
        );
        Path normalized = dataDirectory.toAbsolutePath().normalize();
        this.importsDirectory = normalized.resolve("imports");
        this.stagingDirectory = normalized.resolve("staging");
        this.workflowEventsDirectory = normalized.resolve("workflow").resolve("case-events");
        Files.createDirectories(importsDirectory);
        Files.createDirectories(stagingDirectory);
        Files.createDirectories(workflowEventsDirectory);
        recoverStoredImports();
        recoverCaseEvents();
    }

    public CreateResult create(
            InputStream source,
            long declaredLength,
            String sourceProfileId,
            String idempotencyKey
    ) throws IOException {
        Objects.requireNonNull(source, "source");
        String profile = requireText(sourceProfileId, "sourceProfileId", 128);
        String key = requireText(idempotencyKey, "Idempotency-Key", 128);
        if (key.length() < 8) {
            throw new InvalidRequestException("Idempotency-Key must contain at least 8 characters");
        }
        if (declaredLength > maximumUploadBytes) {
            throw new UploadTooLargeException(maximumUploadBytes);
        }

        Path staged = Files.createTempFile(stagingDirectory, "csv-upload-", ".tmp");
        boolean retained = false;
        try {
            long copied = copyLimited(source, staged);
            if (copied == 0) {
                throw new InvalidRequestException("The CSV request body is empty");
            }

            AnalysisReport report = new WazuhCsvAnalyzer(profile).analyze(staged, PREVIEW_LIMIT);
            String contentIdentity = fileIdentity(profile, report.fileSha256());

            synchronized (mutationLock) {
                UUID previousKeyImportId = createIdempotency.get(key);
                if (previousKeyImportId != null) {
                    StoredImport previous = imports.get(previousKeyImportId);
                    if (previous != null && previous.run().fileSha256().equals(report.fileSha256())
                            && previous.run().sourceProfileId().equals(profile)) {
                        return new CreateResult(snapshot(previous), true, "IDEMPOTENCY_KEY");
                    }
                    throw new IdempotencyConflictException(
                            "Idempotency-Key was already used with a different file or source profile");
                }

                UUID previousFileImportId = fileIdentity.get(contentIdentity);
                if (previousFileImportId != null) {
                    StoredImport previous = imports.get(previousFileImportId);
                    if (previous != null) {
                        createIdempotency.put(key, previousFileImportId);
                        return new CreateResult(snapshot(previous), true, "FILE_SHA256");
                    }
                }

                UUID importId = UUID.randomUUID();
                Instant createdAt = clock.instant();
                Path importDirectory = importsDirectory.resolve(importId.toString());
                Files.createDirectory(importDirectory);
                Path rawEvidence = importDirectory.resolve("source.csv");
                move(staged, rawEvidence);
                retained = true;

                CsvImportRun run = CsvImportRun.uploaded(
                        importId,
                        LOCAL_TENANT,
                        profile,
                        report.fileSha256(),
                        createdAt
                );
                run.startValidation();
                run.previewReady(report);
                StoredImport stored = new StoredImport(run, rawEvidence, importDirectory, key);
                writeAnalysis(stored);
                writeMetadata(stored);
                imports.put(importId, stored);
                createIdempotency.put(key, importId);
                fileIdentity.put(contentIdentity, importId);
                return new CreateResult(snapshot(stored), false, null);
            }
        } finally {
            if (!retained) {
                Files.deleteIfExists(staged);
            }
        }
    }

    public Optional<Map<String, Object>> find(UUID importId) {
        Objects.requireNonNull(importId, "importId");
        synchronized (mutationLock) {
            StoredImport stored = imports.get(importId);
            return stored == null ? Optional.empty() : Optional.of(snapshot(stored));
        }
    }

    public ConfirmResult confirm(UUID importId) throws IOException {
        Objects.requireNonNull(importId, "importId");
        synchronized (mutationLock) {
            StoredImport stored = imports.get(importId);
            if (stored == null) {
                throw new ImportNotFoundException(importId);
            }
            CsvImportRun run = stored.run();
            if (run.status() == CsvImportStatus.COMPLETED) {
                return new ConfirmResult(snapshot(stored), true);
            }
            if (run.status() != CsvImportStatus.PREVIEW_READY) {
                throw new InvalidImportStateException(
                        "Import " + importId + " cannot be confirmed while it is " + run.status());
            }

            DomainMaterializationResult materialization = domainCatalog.materialize(
                    importId,
                    stored.rawEvidence(),
                    run.sourceProfileId()
            );
            canonicalProjection.synchronizeImport(new ProjectionImport(
                    importId,
                    stored.rawEvidence(),
                    run.sourceProfileId(),
                    run.analysisReport(),
                    materialization,
                    run.createdAt()
            ));
            materializations.put(importId, materialization);
            writeMaterialization(stored, materialization);

            run.startImport();
            run.startReconciliation();
            run.complete();
            writeMetadata(stored);
            return new ConfirmResult(snapshot(stored), false);
        }
    }

    public Map<String, Object> catalogSummary() {
        return readCatalog.snapshot().toMap();
    }

    public Map<String, Object> casePreview(int limit) {
        return readCatalog.queryCases(CaseQuery.firstPage(limit)).toMap();
    }

    public Map<String, Object> queryCases(CaseQuery query) {
        return readCatalog.queryCases(query).toMap();
    }

    public Optional<Map<String, Object>> caseDetail(String caseId) {
        return readCatalog.caseDetail(caseId);
    }

    public CaseActionResult actOnCase(
            String caseId,
            CaseActionCommand command,
            String idempotencyKey
    ) throws IOException {
        return actOnCase(caseId, command, idempotencyKey, LOCAL_ACTOR, LOCAL_ACTOR_ASSURANCE);
    }

    public CaseActionResult actOnCase(
            String caseId,
            CaseActionCommand command,
            String idempotencyKey,
            String actorId,
            String actorAssurance
    ) throws IOException {
        synchronized (mutationLock) {
            PreparedCaseAction prepared = domainCatalog.prepareCaseAction(
                    nextWorkflowSequence,
                    caseId,
                    command,
                    idempotencyKey,
                    actorId,
                    actorAssurance,
                    clock.instant()
            );
            if (!prepared.replayed()) {
                writeCaseEvent(prepared.event());
                nextWorkflowSequence = Math.max(nextWorkflowSequence, prepared.event().sequence() + 1);
            }
            Map<String, Object> caseView = domainCatalog.applyCaseEvent(prepared.event());
            canonicalProjection.synchronizeCaseEvent(prepared.event());
            caseView = readCatalog.caseDetail(caseId).orElse(caseView);
            return new CaseActionResult(caseView, prepared.event().toMap(), prepared.replayed());
        }
    }

    public Map<String, Object> health() {
        Map<String, Object> projectionHealth = canonicalProjection.health();
        String projectionStatus = Objects.toString(projectionHealth.get("status"), "UNKNOWN");
        boolean projectionHealthy = projectionStatus.equals("UP")
                || projectionStatus.equals("NOT_CONFIGURED");
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("status", recoveryWarnings.isEmpty() && projectionHealthy ? "UP" : "DEGRADED");
        health.put("contractId", CsvContractV1.ID);
        health.put("catalogBackend", readCatalog.backend());
        health.put("canonicalProjection", projectionHealth);
        health.put("storedImports", imports.size());
        health.put("recoveryWarningCount", recoveryWarnings.size());
        health.put("maximumUploadBytes", maximumUploadBytes);
        CatalogSnapshot catalog = readCatalog.snapshot();
        health.put("materializedImports", catalog.materializedImports());
        health.put("observations", catalog.observations());
        health.put("cases", catalog.cases());
        return health;
    }

    public List<String> recoveryWarnings() {
        synchronized (recoveryWarnings) {
            return List.copyOf(recoveryWarnings);
        }
    }

    private long copyLimited(InputStream input, Path destination) throws IOException {
        long total = 0;
        byte[] buffer = new byte[64 * 1024];
        try (OutputStream output = Files.newOutputStream(
                destination,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
        )) {
            int read;
            while ((read = input.read(buffer)) != -1) {
                total += read;
                if (total > maximumUploadBytes) {
                    throw new UploadTooLargeException(maximumUploadBytes);
                }
                output.write(buffer, 0, read);
            }
        }
        return total;
    }

    private void recoverStoredImports() throws IOException {
        try (Stream<Path> children = Files.list(importsDirectory)) {
            children.filter(Files::isDirectory)
                    .sorted(Comparator.comparing(Path::toString))
                    .forEach(this::recoverOneSafely);
        }
    }

    private void recoverCaseEvents() throws IOException {
        try (Stream<Path> events = Files.list(workflowEventsDirectory)) {
            for (Path eventPath : events
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".properties"))
                    .sorted(Comparator.comparing(Path::toString))
                    .toList()) {
                recoverCaseEventSafely(eventPath);
            }
        }
    }

    private void recoverCaseEventSafely(Path eventPath) {
        String filename = eventPath.getFileName().toString();
        try {
            if (filename.length() < 21 || filename.charAt(20) != '-') {
                throw new IOException("Workflow event filename has no sequence prefix");
            }
            long filenameSequence = Long.parseLong(filename.substring(0, 20));
            nextWorkflowSequence = Math.max(nextWorkflowSequence, filenameSequence + 1);
            Properties properties = new Properties();
            try (InputStream input = Files.newInputStream(eventPath)) {
                properties.load(input);
            }
            CaseAuditEvent event = CaseAuditEvent.fromProperties(properties);
            String expectedPrefix = String.format("%020d-", event.sequence());
            if (!filename.startsWith(expectedPrefix)) {
                throw new IOException("Workflow event filename does not match its sequence");
            }
            domainCatalog.applyCaseEvent(event);
            canonicalProjection.synchronizeCaseEvent(event);
            nextWorkflowSequence = Math.max(nextWorkflowSequence, event.sequence() + 1);
        } catch (Exception exception) {
            String message = exception.getMessage() == null
                    ? exception.getClass().getSimpleName()
                    : exception.getMessage();
            synchronized (recoveryWarnings) {
                recoveryWarnings.add(filename + ": " + message);
            }
        }
    }

    private void recoverOneSafely(Path directory) {
        try {
            recoverOne(directory);
        } catch (Exception exception) {
            String message = exception.getMessage() == null
                    ? exception.getClass().getSimpleName()
                    : exception.getMessage();
            synchronized (recoveryWarnings) {
                recoveryWarnings.add(directory.getFileName() + ": " + message);
            }
        }
    }

    private void recoverOne(Path directory) throws IOException {
        Path metadataPath = directory.resolve("metadata.properties");
        Path rawEvidence = directory.resolve("source.csv");
        if (!Files.isRegularFile(metadataPath) || !Files.isRegularFile(rawEvidence)) {
            throw new IOException("Stored import is missing metadata.properties or source.csv");
        }

        Properties metadata = new Properties();
        try (InputStream input = Files.newInputStream(metadataPath)) {
            metadata.load(input);
        }
        UUID importId = UUID.fromString(requiredProperty(metadata, "importId"));
        if (!directory.getFileName().toString().equals(importId.toString())) {
            throw new IOException("Import directory does not match metadata importId");
        }
        String tenantId = requiredProperty(metadata, "tenantId");
        String sourceProfileId = requiredProperty(metadata, "sourceProfileId");
        String expectedHash = requiredProperty(metadata, "fileSha256");
        Instant createdAt = Instant.parse(requiredProperty(metadata, "createdAt"));
        CsvImportStatus storedStatus = CsvImportStatus.valueOf(requiredProperty(metadata, "status"));
        String creationKey = requiredProperty(metadata, "createIdempotencyKey");

        AnalysisReport report = new WazuhCsvAnalyzer(sourceProfileId).analyze(rawEvidence, PREVIEW_LIMIT);
        if (!expectedHash.equals(report.fileSha256())) {
            throw new IOException("Stored source.csv hash does not match metadata");
        }

        CsvImportRun run = CsvImportRun.uploaded(
                importId,
                tenantId,
                sourceProfileId,
                expectedHash,
                createdAt
        );
        restoreState(run, report, storedStatus, metadata.getProperty("terminalReason"));
        StoredImport stored = new StoredImport(run, rawEvidence, directory, creationKey);
        if (storedStatus == CsvImportStatus.COMPLETED) {
            DomainMaterializationResult rebuilt = domainCatalog.materialize(
                    importId,
                    rawEvidence,
                    sourceProfileId
            );
            DomainMaterializationResult storedMaterialization = readMaterialization(metadata, importId)
                    .orElse(rebuilt);
            materializations.put(importId, storedMaterialization);
            try {
                canonicalProjection.synchronizeImport(new ProjectionImport(
                        importId,
                        rawEvidence,
                        sourceProfileId,
                        report,
                        storedMaterialization,
                        createdAt
                ));
            } catch (IOException exception) {
                synchronized (recoveryWarnings) {
                    recoveryWarnings.add(
                            importId + ": PostgreSQL projection recovery: " + exception.getMessage());
                }
            }
        }
        imports.put(importId, stored);
        createIdempotency.put(creationKey, importId);
        fileIdentity.put(fileIdentity(sourceProfileId, expectedHash), importId);
    }

    private static void restoreState(
            CsvImportRun run,
            AnalysisReport report,
            CsvImportStatus status,
            String terminalReason
    ) {
        if (status == CsvImportStatus.UPLOADED) {
            return;
        }
        run.startValidation();
        if (status == CsvImportStatus.VALIDATING) {
            return;
        }
        if (status == CsvImportStatus.REJECTED) {
            run.reject(requireRecoveredReason(terminalReason));
            return;
        }
        run.previewReady(report);
        if (status == CsvImportStatus.PREVIEW_READY) {
            return;
        }
        run.startImport();
        if (status == CsvImportStatus.IMPORTING) {
            return;
        }
        if (status == CsvImportStatus.FAILED) {
            run.fail(requireRecoveredReason(terminalReason));
            return;
        }
        if (status == CsvImportStatus.PARTIAL) {
            run.partial(requireRecoveredReason(terminalReason));
            return;
        }
        run.startReconciliation();
        if (status == CsvImportStatus.RECONCILING) {
            return;
        }
        if (status == CsvImportStatus.COMPLETED) {
            run.complete();
            return;
        }
        throw new IllegalArgumentException("Unsupported recovered status: " + status);
    }

    private static String requireRecoveredReason(String value) {
        return value == null || value.isBlank() ? "Recovered terminal import" : value;
    }

    private static String requiredProperty(Properties properties, String key) throws IOException {
        String value = properties.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IOException("Missing metadata property: " + key);
        }
        return value;
    }

    private void writeAnalysis(StoredImport stored) throws IOException {
        Path output = stored.directory().resolve("analysis.json");
        Files.writeString(
                output,
                JsonOutput.pretty(stored.run().analysisReport().toMap()),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
        );
    }

    private void writeMaterialization(
            StoredImport stored,
            DomainMaterializationResult materialization
    ) throws IOException {
        Path target = stored.directory().resolve("materialization.json");
        Path temporary = stored.directory().resolve("materialization.json.tmp");
        Files.writeString(
                temporary,
                JsonOutput.pretty(materialization.toMap()),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
        );
        move(temporary, target);
    }

    private void writeCaseEvent(CaseAuditEvent event) throws IOException {
        String filename = String.format("%020d-%s.properties", event.sequence(), event.eventId());
        Path target = workflowEventsDirectory.resolve(filename);
        Path temporary = workflowEventsDirectory.resolve(filename + ".tmp");
        try (OutputStream output = Files.newOutputStream(
                temporary,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
        )) {
            event.toProperties().store(output, "RBVM immutable case audit event");
        }
        move(temporary, target);
    }

    private void writeMetadata(StoredImport stored) throws IOException {
        CsvImportRun run = stored.run();
        Properties metadata = new Properties();
        metadata.setProperty("importId", run.importId().toString());
        metadata.setProperty("tenantId", run.tenantId());
        metadata.setProperty("sourceProfileId", run.sourceProfileId());
        metadata.setProperty("fileSha256", run.fileSha256());
        metadata.setProperty("createdAt", run.createdAt().toString());
        metadata.setProperty("status", run.status().name());
        metadata.setProperty("createIdempotencyKey", stored.creationIdempotencyKey());
        if (run.terminalReason() != null) {
            metadata.setProperty("terminalReason", run.terminalReason());
        }
        DomainMaterializationResult materialization = materializations.get(run.importId());
        if (materialization != null) {
            writeMaterializationProperties(metadata, materialization);
        }

        Path target = stored.directory().resolve("metadata.properties");
        Path temporary = stored.directory().resolve("metadata.properties.tmp");
        try (OutputStream output = Files.newOutputStream(
                temporary,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
        )) {
            metadata.store(output, "RBVM CSV import metadata");
        }
        move(temporary, target);
    }

    private Map<String, Object> snapshot(StoredImport stored) {
        CsvImportRun run = stored.run();
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("importId", run.importId().toString());
        output.put("tenantId", run.tenantId());
        output.put("sourceProfileId", run.sourceProfileId());
        output.put("contractId", CsvContractV1.ID);
        output.put("semantics", "POSITIVE_OBSERVATION_EXPORT");
        output.put("commitScope", "CANONICAL_DOMAIN_AND_RAW_EVIDENCE");
        output.put("status", run.status().name());
        output.put("createdAt", run.createdAt().toString());
        output.put("fileSha256", run.fileSha256());
        output.put("terminalReason", run.terminalReason());
        output.put("analysis", run.analysisReport() == null ? null : run.analysisReport().toMap());
        DomainMaterializationResult materialization = materializations.get(run.importId());
        output.put("materialization", materialization == null ? null : materialization.toMap());

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("stored", Files.isRegularFile(stored.rawEvidence()));
        evidence.put("relativePath", "imports/" + run.importId() + "/source.csv");
        output.put("rawEvidence", evidence);
        return output;
    }

    private static void writeMaterializationProperties(
            Properties metadata,
            DomainMaterializationResult value
    ) {
        metadata.setProperty("materialization.acceptedObservations",
                Long.toString(value.acceptedObservations()));
        metadata.setProperty("materialization.insertedObservations",
                Long.toString(value.insertedObservations()));
        metadata.setProperty("materialization.duplicateObservations",
                Long.toString(value.duplicateObservations()));
        metadata.setProperty("materialization.newAssets", Long.toString(value.newAssets()));
        metadata.setProperty("materialization.newVulnerabilities",
                Long.toString(value.newVulnerabilities()));
        metadata.setProperty("materialization.newComponents", Long.toString(value.newComponents()));
        metadata.setProperty("materialization.newExposures", Long.toString(value.newExposures()));
        metadata.setProperty("materialization.updatedExposures",
                Long.toString(value.updatedExposures()));
        metadata.setProperty("materialization.newCases", Long.toString(value.newCases()));
        metadata.setProperty("materialization.updatedCases", Long.toString(value.updatedCases()));
        metadata.setProperty("materialization.materializedAt", value.materializedAt().toString());
    }

    private static Optional<DomainMaterializationResult> readMaterialization(
            Properties metadata,
            UUID importId
    ) {
        String accepted = metadata.getProperty("materialization.acceptedObservations");
        if (accepted == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(new DomainMaterializationResult(
                    importId,
                    false,
                    Long.parseLong(accepted),
                    Long.parseLong(requiredProperty(metadata, "materialization.insertedObservations")),
                    Long.parseLong(requiredProperty(metadata, "materialization.duplicateObservations")),
                    Long.parseLong(requiredProperty(metadata, "materialization.newAssets")),
                    Long.parseLong(requiredProperty(metadata, "materialization.newVulnerabilities")),
                    Long.parseLong(requiredProperty(metadata, "materialization.newComponents")),
                    Long.parseLong(requiredProperty(metadata, "materialization.newExposures")),
                    Long.parseLong(requiredProperty(metadata, "materialization.updatedExposures")),
                    Long.parseLong(requiredProperty(metadata, "materialization.newCases")),
                    Long.parseLong(requiredProperty(metadata, "materialization.updatedCases")),
                    Instant.parse(requiredProperty(metadata, "materialization.materializedAt"))
            ));
        } catch (IOException | IllegalArgumentException exception) {
            throw new IllegalStateException("Invalid stored materialization metadata", exception);
        }
    }

    private static String fileIdentity(String sourceProfileId, String hash) {
        return sourceProfileId + '\u001f' + hash;
    }

    @Override
    public void close() {
        canonicalProjection.close();
    }

    private static String requireText(String value, String field, int maximumLength) {
        if (value == null || value.isBlank()) {
            throw new InvalidRequestException(field + " is required");
        }
        String trimmed = value.trim();
        if (trimmed.length() > maximumLength) {
            throw new InvalidRequestException(field + " must not exceed " + maximumLength + " characters");
        }
        return trimmed;
    }

    private static void move(Path source, Path target) throws IOException {
        try {
            Files.move(
                    source,
                    target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING
            );
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private record StoredImport(
            CsvImportRun run,
            Path rawEvidence,
            Path directory,
            String creationIdempotencyKey
    ) {
    }

    public record CreateResult(Map<String, Object> importView, boolean replayed, String replayReason) {
    }

    public record ConfirmResult(Map<String, Object> importView, boolean replayed) {
    }

    public record CaseActionResult(
            Map<String, Object> caseView,
            Map<String, Object> auditEvent,
            boolean replayed
    ) {
        public Map<String, Object> toMap() {
            Map<String, Object> output = new LinkedHashMap<>();
            output.put("replayed", replayed);
            output.put("case", caseView);
            output.put("auditEvent", auditEvent);
            return output;
        }
    }

    public static final class InvalidRequestException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        public InvalidRequestException(String message) {
            super(message);
        }
    }

    public static final class UploadTooLargeException extends IOException {
        private static final long serialVersionUID = 1L;
        private final long maximumBytes;

        public UploadTooLargeException(long maximumBytes) {
            super("CSV exceeds the maximum upload size of " + maximumBytes + " bytes");
            this.maximumBytes = maximumBytes;
        }

        public long maximumBytes() {
            return maximumBytes;
        }
    }

    public static final class IdempotencyConflictException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public IdempotencyConflictException(String message) {
            super(message);
        }
    }

    public static final class ImportNotFoundException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        public ImportNotFoundException(UUID importId) {
            super("CSV import was not found: " + importId);
        }
    }

    public static final class InvalidImportStateException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public InvalidImportStateException(String message) {
            super(message);
        }
    }
}
