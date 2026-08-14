package io.rbvm.domain;

import io.rbvm.csv.AnalysisReport;
import io.rbvm.csv.CsvSeverity;
import io.rbvm.csv.FindingStatus;
import io.rbvm.csv.WazuhCsvAnalyzer;
import io.rbvm.csv.WazuhObservation;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Transactional derived catalog used by the local runtime and domain tests.
 *
 * <p>A complete copy is mutated and swapped only after the CSV finishes, so a
 * malformed row cannot leave a partially materialized catalog. PostgreSQL uses
 * the same natural keys and transaction boundary described by the migration.</p>
 */
public final class InMemoryDomainCatalog implements DomainCatalog {
    private static final String LOCAL_TENANT = "local";

    private final Clock clock;
    private Projection projection = new Projection();
    private final Map<UUID, DomainMaterializationResult> results = new HashMap<>();
    private final Map<String, CaseAuditEvent> actionIdempotency = new HashMap<>();
    private final Map<String, List<CaseAuditEvent>> auditEventsByCase = new HashMap<>();
    private long revision;

    public InMemoryDomainCatalog() {
        this(Clock.systemUTC());
    }

    InMemoryDomainCatalog(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public synchronized DomainMaterializationResult materialize(
            UUID importId,
            Path csvPath,
            String sourceProfileId,
            String contractId
    ) throws IOException {
        Objects.requireNonNull(importId, "importId");
        Objects.requireNonNull(csvPath, "csvPath");
        Objects.requireNonNull(sourceProfileId, "sourceProfileId");

        DomainMaterializationResult previous = results.get(importId);
        if (previous != null) {
            return previous.asReplay();
        }

        Projection working = new Projection(projection);
        Accumulator accumulator = new Accumulator(importId);
        AnalysisReport analysis = new WazuhCsvAnalyzer(sourceProfileId, contractId).analyze(
                csvPath,
                0,
                observation -> working.apply(importId, observation, accumulator)
        );
        if (analysis.acceptedRows() != accumulator.acceptedObservations) {
            throw new IllegalStateException("Analyzer and domain materializer accepted-row counts diverged");
        }
        working.recomputeCases(accumulator.touchedCaseKeys);

        DomainMaterializationResult result = accumulator.result(clock.instant());
        projection = working;
        results.put(importId, result);
        revision++;
        return result;
    }

    @Override
    public synchronized CatalogSnapshot snapshot() {
        Map<String, Long> severityDistribution = new LinkedHashMap<>();
        for (CsvSeverity severity : CsvSeverity.values()) {
            severityDistribution.put(severity.name(), 0L);
        }
        for (CaseEntry item : projection.cases.values()) {
            severityDistribution.compute(item.currentSeverity.name(), (ignored, count) -> count + 1);
        }
        Map<String, Long> statusDistribution = new LinkedHashMap<>();
        for (CaseStatus status : CaseStatus.values()) {
            statusDistribution.put(status.name(), 0L);
        }
        for (CaseEntry item : projection.cases.values()) {
            statusDistribution.compute(item.status.name(), (ignored, count) -> count + 1);
        }
        long links = projection.importObservationLinks.values().stream().mapToLong(Set::size).sum();
        long changed = projection.exposures.values().stream()
                .filter(item -> item.observedSeverities.size() > 1)
                .count();
        long conflicts = projection.exposures.values().stream()
                .filter(item -> item.timestampSeverityConflict)
                .count();
        long openCases = projection.cases.values().stream()
                .filter(item -> item.status == CaseStatus.OPEN)
                .count();
        long sourceResolvedCases = projection.cases.values().stream()
                .filter(item -> item.status == CaseStatus.SOURCE_RESOLVED)
                .count();
        return new CatalogSnapshot(
                results.size(),
                projection.observations.size(),
                links,
                projection.assets.size(),
                projection.vulnerabilities.size(),
                projection.components.size(),
                projection.exposures.size(),
                projection.cases.size(),
                openCases,
                sourceResolvedCases,
                changed,
                conflicts,
                Collections.unmodifiableMap(new LinkedHashMap<>(severityDistribution)),
                Collections.unmodifiableMap(new LinkedHashMap<>(statusDistribution))
        );
    }

    @Override
    public synchronized CasePage queryCases(CaseQuery query) {
        Objects.requireNonNull(query, "query");
        int offset = decodeCursor(query.cursor());
        Instant now = clock.instant();
        String cveFilter = query.cveContains() == null
                ? null
                : query.cveContains().toUpperCase(Locale.ROOT);
        String assetFilter = query.assetContains() == null
                ? null
                : query.assetContains().toLowerCase(Locale.ROOT);

        List<CaseEntry> matching = projection.cases.values().stream()
                .filter(item -> query.severities().isEmpty()
                        || query.severities().contains(item.currentSeverity))
                .filter(item -> query.statuses().isEmpty() || query.statuses().contains(item.status))
                .filter(item -> cveFilter == null || item.cveId.contains(cveFilter))
                .filter(item -> assetMatches(item, assetFilter))
                .sorted(caseComparator())
                .toList();
        if (offset > matching.size()) {
            throw new StaleCaseCursorException("Case cursor points beyond the current result set");
        }

        int end = Math.min(matching.size(), offset + query.limit());
        List<Map<String, Object>> page = new ArrayList<>();
        for (CaseEntry item : matching.subList(offset, end)) {
            page.add(item.toMap(projection.assets.get(item.assetKey), now));
        }
        String next = query.limit() > 0 && end < matching.size() ? encodeCursor(end) : null;
        return new CasePage(revision, snapshot(), page, next);
    }

    @Override
    public synchronized Optional<Map<String, Object>> caseDetail(String caseId) {
        CaseEntry item = findCase(caseId);
        return item == null ? Optional.empty() : Optional.of(caseDetail(item));
    }

    @Override
    public synchronized PreparedCaseAction prepareCaseAction(
            long sequence,
            String caseId,
            CaseActionCommand command,
            String idempotencyKey,
            String actorId,
            String actorAssurance,
            Instant occurredAt
    ) {
        if (sequence < 1) {
            throw new IllegalArgumentException("sequence must be positive");
        }
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(occurredAt, "occurredAt");
        String normalizedKey = requireText(idempotencyKey, "Idempotency-Key", 8, 128);
        String normalizedActor = requireText(actorId, "actorId", 1, 200);
        String normalizedAssurance = requireText(actorAssurance, "actorAssurance", 1, 100);
        String requestFingerprint = actionFingerprint(command);
        String idempotencyScope = key(caseId, normalizedKey);
        CaseAuditEvent previous = actionIdempotency.get(idempotencyScope);
        if (previous != null) {
            if (!previous.requestFingerprint().equals(requestFingerprint)) {
                throw new CaseWorkflowConflictException(
                        "Idempotency-Key was already used for a different case action");
            }
            if (!previous.actorId().equals(normalizedActor)) {
                throw new CaseWorkflowConflictException(
                        "Idempotency-Key was already used by a different authenticated actor");
            }
            return new PreparedCaseAction(previous, true);
        }

        CaseEntry item = findCase(caseId);
        if (item == null) {
            throw new CaseNotFoundException(caseId);
        }
        CaseStatus target = validateTransition(item, command, occurredAt);
        String eventNaturalKey = key(
                Long.toString(sequence),
                caseId,
                normalizedKey,
                requestFingerprint
        );
        CaseAuditEvent event = new CaseAuditEvent(
                sequence,
                publicId("case-event", eventNaturalKey),
                caseId,
                item.workflowVersion + 1,
                normalizedKey,
                requestFingerprint,
                command.action(),
                item.status,
                target,
                command.reason(),
                command.expiresAt(),
                command.evidenceReference(),
                normalizedActor,
                normalizedAssurance,
                occurredAt
        );
        return new PreparedCaseAction(event, false);
    }

    @Override
    public synchronized Map<String, Object> applyCaseEvent(CaseAuditEvent event) {
        Objects.requireNonNull(event, "event");
        String idempotencyScope = key(event.caseId(), event.idempotencyKey());
        CaseAuditEvent previous = actionIdempotency.get(idempotencyScope);
        if (previous != null) {
            if (!previous.eventId().equals(event.eventId())) {
                throw new CaseWorkflowConflictException(
                        "Stored case action conflicts with an existing Idempotency-Key");
            }
            CaseEntry replayed = findCase(event.caseId());
            if (replayed == null) {
                throw new CaseNotFoundException(event.caseId());
            }
            return caseDetail(replayed);
        }

        CaseEntry item = findCase(event.caseId());
        if (item == null) {
            throw new CaseNotFoundException(event.caseId());
        }
        if (item.workflowVersion + 1 != event.caseVersion()) {
            throw new CaseWorkflowConflictException(
                    "Case workflow version mismatch: expected " + (item.workflowVersion + 1)
                            + " but event contains " + event.caseVersion());
        }
        if (item.status != event.fromStatus()) {
            throw new CaseWorkflowConflictException(
                    "Case status mismatch: expected " + item.status + " but event starts at "
                            + event.fromStatus());
        }

        item.status = event.toStatus();
        item.workflowVersion = event.caseVersion();
        item.lastWorkflowAt = event.occurredAt();
        switch (event.action()) {
            case ACCEPT_RISK -> {
                item.riskAcceptedUntil = event.expiresAt();
                item.decisionReason = event.reason();
                item.decisionEvidence = event.evidenceReference();
            }
            case MARK_FALSE_POSITIVE, CLOSE_MANUAL -> {
                item.riskAcceptedUntil = null;
                item.decisionReason = event.reason();
                item.decisionEvidence = event.evidenceReference();
            }
            case REOPEN -> {
                item.riskAcceptedUntil = null;
                item.decisionReason = null;
                item.decisionEvidence = null;
            }
            case COMMENT -> {
                // A comment is audit-only and does not overwrite the current decision metadata.
            }
        }
        auditEventsByCase.computeIfAbsent(event.caseId(), ignored -> new ArrayList<>()).add(event);
        actionIdempotency.put(idempotencyScope, event);
        revision++;
        return caseDetail(item);
    }

    private Map<String, Object> caseDetail(CaseEntry item) {
        Instant now = clock.instant();
        Map<String, Object> output = new LinkedHashMap<>(
                item.toMap(projection.assets.get(item.assetKey), now));
        VulnerabilityEntry vulnerability = projection.vulnerabilities.get(item.cveId);
        output.put("description", vulnerability == null ? "" : vulnerability.description);

        List<Map<String, Object>> exposures = item.exposureKeys.stream()
                .map(projection.exposures::get)
                .filter(Objects::nonNull)
                .sorted(Comparator
                        .comparingInt((ExposureEntry exposure) -> severityRank(exposure.currentSeverity))
                        .reversed()
                        .thenComparing(
                                (ExposureEntry exposure) -> exposure.lastObservedAt,
                                Comparator.reverseOrder())
                        .thenComparing(exposure -> exposure.publicId))
                .map(exposure -> exposure.toMap(projection.components.get(exposure.componentKey)))
                .toList();
        output.put("exposures", exposures);
        output.put("auditEvents", auditEventsByCase.getOrDefault(item.publicId, List.of()).stream()
                .map(CaseAuditEvent::toMap)
                .toList());
        return output;
    }

    private CaseEntry findCase(String caseId) {
        if (caseId == null) {
            return null;
        }
        String naturalKey = projection.caseNaturalKeysByPublicId.get(caseId);
        return naturalKey == null ? null : projection.cases.get(naturalKey);
    }

    private boolean assetMatches(CaseEntry item, String filter) {
        if (filter == null) {
            return true;
        }
        AssetEntry asset = projection.assets.get(item.assetKey);
        return asset != null && (asset.observedName.toLowerCase(Locale.ROOT).contains(filter)
                || asset.normalizedObservedName.contains(filter));
    }

    private static Comparator<CaseEntry> caseComparator() {
        return Comparator
                .comparingInt((CaseEntry item) -> severityRank(item.currentSeverity)).reversed()
                .thenComparing((CaseEntry item) -> item.lastObservedAt, Comparator.reverseOrder())
                .thenComparing(item -> item.publicId);
    }

    private int decodeCursor(String cursor) {
        if (cursor == null) {
            return 0;
        }
        try {
            String decoded = new String(
                    Base64.getUrlDecoder().decode(cursor),
                    StandardCharsets.UTF_8
            );
            String[] parts = decoded.split(":", -1);
            if (parts.length != 2) {
                throw new IllegalArgumentException("invalid parts");
            }
            long cursorRevision = Long.parseLong(parts[0]);
            int offset = Integer.parseInt(parts[1]);
            if (cursorRevision != revision) {
                throw new StaleCaseCursorException(
                        "Case catalog changed from revision " + cursorRevision + " to " + revision);
            }
            if (offset < 0) {
                throw new IllegalArgumentException("negative offset");
            }
            return offset;
        } catch (StaleCaseCursorException exception) {
            throw exception;
        } catch (IllegalArgumentException exception) {
            throw new InvalidCaseActionException("cursor is invalid");
        }
    }

    private String encodeCursor(int offset) {
        String value = revision + ":" + offset;
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static CaseStatus validateTransition(
            CaseEntry item,
            CaseActionCommand command,
            Instant occurredAt
    ) {
        return switch (command.action()) {
            case ACCEPT_RISK -> {
                if (item.status != CaseStatus.OPEN && item.status != CaseStatus.ACCEPTED_RISK) {
                    throw invalidTransition(item, command);
                }
                if (!command.expiresAt().isAfter(occurredAt)) {
                    throw new InvalidCaseActionException("expiresAt must be later than the action time");
                }
                yield CaseStatus.ACCEPTED_RISK;
            }
            case MARK_FALSE_POSITIVE -> {
                if (item.status != CaseStatus.OPEN && item.status != CaseStatus.ACCEPTED_RISK) {
                    throw invalidTransition(item, command);
                }
                yield CaseStatus.FALSE_POSITIVE;
            }
            case CLOSE_MANUAL -> {
                if (item.status != CaseStatus.OPEN && item.status != CaseStatus.ACCEPTED_RISK) {
                    throw invalidTransition(item, command);
                }
                yield CaseStatus.CLOSED_MANUAL;
            }
            case REOPEN -> {
                if (item.status == CaseStatus.OPEN || item.status == CaseStatus.SOURCE_RESOLVED) {
                    throw invalidTransition(item, command);
                }
                yield CaseStatus.OPEN;
            }
            case COMMENT -> {
                if (item.status == CaseStatus.SOURCE_RESOLVED) {
                    throw invalidTransition(item, command);
                }
                yield item.status;
            }
        };
    }

    private static InvalidCaseActionException invalidTransition(
            CaseEntry item,
            CaseActionCommand command
    ) {
        return new InvalidCaseActionException(
                "Action " + command.action() + " is not allowed while case is " + item.status);
    }

    private static String actionFingerprint(CaseActionCommand command) {
        return publicId("case-action-request", key(
                command.action().name(),
                command.reason(),
                command.expiresAt() == null ? "" : command.expiresAt().toString(),
                command.evidenceReference() == null ? "" : command.evidenceReference()
        ));
    }

    private static String requireText(
            String value,
            String field,
            int minimumLength,
            int maximumLength
    ) {
        if (value == null || value.isBlank()) {
            throw new InvalidCaseActionException(field + " is required");
        }
        String trimmed = value.trim();
        if (trimmed.length() < minimumLength || trimmed.length() > maximumLength) {
            throw new InvalidCaseActionException(
                    field + " must contain between " + minimumLength + " and " + maximumLength
                            + " characters");
        }
        return trimmed;
    }

    @Override
    public synchronized boolean isMaterialized(UUID importId) {
        return results.containsKey(importId);
    }

    private static int severityRank(CsvSeverity severity) {
        return switch (severity) {
            case UNKNOWN -> 0;
            case LOW -> 1;
            case MEDIUM -> 2;
            case HIGH -> 3;
            case CRITICAL -> 4;
        };
    }

    private static CsvSeverity maximumSeverity(CsvSeverity first, CsvSeverity second) {
        return severityRank(first) >= severityRank(second) ? first : second;
    }

    private static String key(String... values) {
        return String.join("\u001f", values);
    }

    private static String publicId(String namespace, String naturalKey) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
        updateDigest(digest, namespace);
        updateDigest(digest, naturalKey);
        StringBuilder output = new StringBuilder(64);
        for (byte value : digest.digest()) {
            output.append(String.format("%02x", value));
        }
        return output.toString();
    }

    private static void updateDigest(MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
        digest.update(bytes);
    }

    private static final class Projection {
        private final Map<String, ObservationEntry> observations;
        private final Map<UUID, Set<String>> importObservationLinks;
        private final Map<String, AssetEntry> assets;
        private final Map<String, VulnerabilityEntry> vulnerabilities;
        private final Map<String, ComponentEntry> components;
        private final Map<String, ExposureEntry> exposures;
        private final Map<String, CaseEntry> cases;
        private final Map<String, String> caseNaturalKeysByPublicId;

        private Projection() {
            observations = new HashMap<>();
            importObservationLinks = new HashMap<>();
            assets = new HashMap<>();
            vulnerabilities = new HashMap<>();
            components = new HashMap<>();
            exposures = new HashMap<>();
            cases = new HashMap<>();
            caseNaturalKeysByPublicId = new HashMap<>();
        }

        private Projection(Projection source) {
            observations = new HashMap<>(source.observations);
            importObservationLinks = new HashMap<>();
            source.importObservationLinks.forEach(
                    (importId, links) -> importObservationLinks.put(importId, new LinkedHashSet<>(links)));
            assets = copy(source.assets, AssetEntry::new);
            vulnerabilities = copy(source.vulnerabilities, VulnerabilityEntry::new);
            components = copy(source.components, ComponentEntry::new);
            exposures = copy(source.exposures, ExposureEntry::new);
            cases = copy(source.cases, CaseEntry::new);
            caseNaturalKeysByPublicId = new HashMap<>(source.caseNaturalKeysByPublicId);
        }

        private void apply(UUID importId, WazuhObservation observation, Accumulator accumulator) {
            accumulator.acceptedObservations++;
            String observationKey = key(
                    LOCAL_TENANT,
                    observation.sourceProfileId(),
                    observation.observationFingerprint()
            );
            importObservationLinks.computeIfAbsent(importId, ignored -> new LinkedHashSet<>())
                    .add(observationKey);
            if (observations.containsKey(observationKey)) {
                accumulator.duplicateObservations++;
                return;
            }

            observations.put(observationKey, new ObservationEntry(importId, observation));
            accumulator.insertedObservations++;

            String assetKey = key(
                    LOCAL_TENANT,
                    observation.sourceProfileId(),
                    observation.agentIdentityKey()
            );
            AssetEntry asset = assets.get(assetKey);
            if (asset == null) {
                asset = new AssetEntry(assetKey, observation);
                assets.put(assetKey, asset);
                accumulator.newAssetKeys.add(assetKey);
            } else {
                asset.observe(observation);
            }

            VulnerabilityEntry vulnerability = vulnerabilities.get(observation.cveId());
            if (vulnerability == null) {
                vulnerability = new VulnerabilityEntry(observation);
                vulnerabilities.put(observation.cveId(), vulnerability);
                accumulator.newVulnerabilityKeys.add(observation.cveId());
            } else {
                vulnerability.observe(observation);
            }

            String componentKey = key(assetKey, observation.affectedProductIdentityKey());
            ComponentEntry component = components.get(componentKey);
            if (component == null) {
                component = new ComponentEntry(componentKey, assetKey, observation);
                components.put(componentKey, component);
                accumulator.newComponentKeys.add(componentKey);
            } else {
                component.observe(observation);
            }

            String caseKey = key(
                    LOCAL_TENANT,
                    observation.sourceProfileId(),
                    observation.agentIdentityKey(),
                    observation.cveId()
            );
            CaseEntry caseEntry = cases.get(caseKey);
            if (caseEntry == null) {
                caseEntry = new CaseEntry(caseKey, assetKey, observation);
                cases.put(caseKey, caseEntry);
                caseNaturalKeysByPublicId.put(caseEntry.publicId, caseKey);
                accumulator.newCaseKeys.add(caseKey);
            } else if (!accumulator.newCaseKeys.contains(caseKey)) {
                accumulator.updatedCaseKeys.add(caseKey);
            }

            String exposureKey = key(caseKey, observation.affectedProductIdentityKey());
            ExposureEntry exposure = exposures.get(exposureKey);
            if (exposure == null) {
                exposure = new ExposureEntry(
                        exposureKey,
                        caseKey,
                        assetKey,
                        componentKey,
                        observation
                );
                exposures.put(exposureKey, exposure);
                accumulator.newExposureKeys.add(exposureKey);
            } else {
                exposure.observe(observation);
                if (!accumulator.newExposureKeys.contains(exposureKey)) {
                    accumulator.updatedExposureKeys.add(exposureKey);
                }
            }
            caseEntry.exposureKeys.add(exposureKey);
            accumulator.touchedCaseKeys.add(caseKey);
        }

        private void recomputeCases(Set<String> caseKeys) {
            for (String caseKey : caseKeys) {
                CaseEntry item = cases.get(caseKey);
                if (item != null) {
                    item.recompute(exposures);
                }
            }
        }

        private static <T> Map<String, T> copy(Map<String, T> source, Copier<T> copier) {
            Map<String, T> output = new HashMap<>();
            source.forEach((key, value) -> output.put(key, copier.copy(value)));
            return output;
        }
    }

    @FunctionalInterface
    private interface Copier<T> {
        T copy(T source);
    }

    private record ObservationEntry(UUID firstImportId, WazuhObservation observation) {
    }

    private static final class AssetEntry {
        private final String publicId;
        private final String sourceProfileId;
        private final String normalizedObservedName;
        private String observedName;
        private String osNameRaw;
        private Instant firstObservedAt;
        private Instant lastObservedAt;

        private AssetEntry(String naturalKey, WazuhObservation observation) {
            publicId = publicId("asset", naturalKey);
            sourceProfileId = observation.sourceProfileId();
            normalizedObservedName = observation.agentIdentityKey();
            observedName = observation.agentObservedName();
            osNameRaw = observation.osNameRaw();
            firstObservedAt = observation.detectedAt();
            lastObservedAt = observation.detectedAt();
        }

        private AssetEntry(AssetEntry source) {
            publicId = source.publicId;
            sourceProfileId = source.sourceProfileId;
            normalizedObservedName = source.normalizedObservedName;
            observedName = source.observedName;
            osNameRaw = source.osNameRaw;
            firstObservedAt = source.firstObservedAt;
            lastObservedAt = source.lastObservedAt;
        }

        private void observe(WazuhObservation observation) {
            if (observation.detectedAt().isBefore(firstObservedAt)) {
                firstObservedAt = observation.detectedAt();
            }
            if (observation.detectedAt().isAfter(lastObservedAt)) {
                lastObservedAt = observation.detectedAt();
                observedName = observation.agentObservedName();
                osNameRaw = observation.osNameRaw();
            }
        }
    }

    private static final class VulnerabilityEntry {
        private final String cveId;
        private String description;
        private Instant descriptionObservedAt;

        private VulnerabilityEntry(WazuhObservation observation) {
            cveId = observation.cveId();
            description = observation.descriptionSnapshot();
            descriptionObservedAt = observation.detectedAt();
        }

        private VulnerabilityEntry(VulnerabilityEntry source) {
            cveId = source.cveId;
            description = source.description;
            descriptionObservedAt = source.descriptionObservedAt;
        }

        private void observe(WazuhObservation observation) {
            if (!observation.descriptionSnapshot().isBlank()
                    && observation.detectedAt().isAfter(descriptionObservedAt)) {
                description = observation.descriptionSnapshot();
                descriptionObservedAt = observation.detectedAt();
            }
        }
    }

    private static final class ComponentEntry {
        private final String publicId;
        private final String assetPublicId;
        private final String normalizedProductName;
        private String observedProductName;
        private String packageVersion;
        private String packageArchitecture;
        private Instant firstObservedAt;
        private Instant lastObservedAt;

        private ComponentEntry(String naturalKey, String assetKey, WazuhObservation observation) {
            publicId = publicId("component", naturalKey);
            assetPublicId = publicId("asset", assetKey);
            normalizedProductName = observation.affectedProductIdentityKey();
            observedProductName = observation.affectedProductObservedName();
            packageVersion = observation.packageVersion();
            packageArchitecture = observation.packageArchitecture();
            firstObservedAt = observation.detectedAt();
            lastObservedAt = observation.detectedAt();
        }

        private ComponentEntry(ComponentEntry source) {
            publicId = source.publicId;
            assetPublicId = source.assetPublicId;
            normalizedProductName = source.normalizedProductName;
            observedProductName = source.observedProductName;
            packageVersion = source.packageVersion;
            packageArchitecture = source.packageArchitecture;
            firstObservedAt = source.firstObservedAt;
            lastObservedAt = source.lastObservedAt;
        }

        private void observe(WazuhObservation observation) {
            if (observation.detectedAt().isBefore(firstObservedAt)) {
                firstObservedAt = observation.detectedAt();
            }
            if (observation.detectedAt().isAfter(lastObservedAt)) {
                lastObservedAt = observation.detectedAt();
                observedProductName = observation.affectedProductObservedName();
                packageVersion = observation.packageVersion();
                packageArchitecture = observation.packageArchitecture();
            }
        }
    }

    private static final class ExposureEntry {
        private final String publicId;
        private final String caseKey;
        private final String assetPublicId;
        private final String componentKey;
        private final String componentPublicId;
        private final String cveId;
        private Instant firstObservedAt;
        private Instant lastObservedAt;
        private Instant currentSeverityObservedAt;
        private FindingStatus findingStatus;
        private Instant lifecycleObservedAt;
        private Instant resolvedAt;
        private final String closurePolicy;
        private CsvSeverity currentSeverity;
        private long observationCount;
        private final Set<CsvSeverity> observedSeverities;
        private boolean timestampSeverityConflict;

        private ExposureEntry(
                String naturalKey,
                String caseKey,
                String assetKey,
                String componentKey,
                WazuhObservation observation
        ) {
            publicId = publicId("exposure", naturalKey);
            this.caseKey = caseKey;
            assetPublicId = publicId("asset", assetKey);
            this.componentKey = componentKey;
            componentPublicId = publicId("component", componentKey);
            cveId = observation.cveId();
            firstObservedAt = observation.detectedAt();
            lastObservedAt = observation.detectedAt();
            currentSeverityObservedAt = observation.detectedAt();
            currentSeverity = observation.severity();
            findingStatus = observation.findingStatus();
            lifecycleObservedAt = observation.evidenceAt();
            resolvedAt = observation.resolvedAt();
            closurePolicy = observation.contractId().equals("WAZUH_CSV_V2")
                    ? "EXPLICIT_SOURCE_EVIDENCE_ONLY" : "POSITIVE_ONLY_NO_AUTO_CLOSE";
            observationCount = 1;
            observedSeverities = new HashSet<>();
            observedSeverities.add(observation.severity());
        }

        private ExposureEntry(ExposureEntry source) {
            publicId = source.publicId;
            caseKey = source.caseKey;
            assetPublicId = source.assetPublicId;
            componentKey = source.componentKey;
            componentPublicId = source.componentPublicId;
            cveId = source.cveId;
            firstObservedAt = source.firstObservedAt;
            lastObservedAt = source.lastObservedAt;
            currentSeverityObservedAt = source.currentSeverityObservedAt;
            currentSeverity = source.currentSeverity;
            findingStatus = source.findingStatus;
            lifecycleObservedAt = source.lifecycleObservedAt;
            resolvedAt = source.resolvedAt;
            closurePolicy = source.closurePolicy;
            observationCount = source.observationCount;
            observedSeverities = new HashSet<>(source.observedSeverities);
            timestampSeverityConflict = source.timestampSeverityConflict;
        }

        private void observe(WazuhObservation observation) {
            observationCount++;
            observedSeverities.add(observation.severity());
            if (observation.detectedAt().isBefore(firstObservedAt)) {
                firstObservedAt = observation.detectedAt();
            }
            if (observation.detectedAt().isAfter(lastObservedAt)) {
                lastObservedAt = observation.detectedAt();
            }
            int order = observation.detectedAt().compareTo(currentSeverityObservedAt);
            if (order > 0) {
                currentSeverityObservedAt = observation.detectedAt();
                currentSeverity = observation.severity();
            } else if (order == 0 && observation.severity() != currentSeverity) {
                timestampSeverityConflict = true;
                currentSeverity = maximumSeverity(currentSeverity, observation.severity());
            }
            int lifecycleOrder = observation.evidenceAt().compareTo(lifecycleObservedAt);
            if (lifecycleOrder > 0 || (lifecycleOrder == 0
                    && observation.findingStatus() == FindingStatus.ACTIVE)) {
                lifecycleObservedAt = observation.evidenceAt();
                findingStatus = observation.findingStatus();
                resolvedAt = observation.resolvedAt();
            }
        }

        private Map<String, Object> toMap(ComponentEntry component) {
            Map<String, Object> output = new LinkedHashMap<>();
            output.put("exposureId", publicId);
            output.put("assetId", assetPublicId);
            output.put("componentId", componentPublicId);
            output.put("cveId", cveId);
            output.put("product", component == null ? "" : component.observedProductName);
            output.put("packageVersion", component == null ? "" : component.packageVersion);
            output.put("packageArchitecture", component == null ? "" : component.packageArchitecture);
            output.put("versionStatus", component == null || component.packageVersion.isBlank()
                    ? "UNKNOWN_FROM_SOURCE" : "OBSERVED_FROM_SOURCE");
            output.put("status", findingStatus.name());
            output.put("lifecycleObservedAt", lifecycleObservedAt.toString());
            output.put("resolvedAt", resolvedAt == null ? null : resolvedAt.toString());
            output.put("currentSeverity", currentSeverity.name());
            output.put("currentSeverityObservedAt", currentSeverityObservedAt.toString());
            output.put("firstObservedAt", firstObservedAt.toString());
            output.put("lastObservedAt", lastObservedAt.toString());
            output.put("observationCount", observationCount);
            output.put("severityChanged", observedSeverities.size() > 1);
            output.put("timestampSeverityConflict", timestampSeverityConflict);
            output.put("closurePolicy", closurePolicy);
            return output;
        }
    }

    private static final class CaseEntry {
        private final String publicId;
        private final String assetKey;
        private final String assetPublicId;
        private final String sourceProfileId;
        private final String cveId;
        private final Set<String> exposureKeys;
        private Instant firstObservedAt;
        private Instant lastObservedAt;
        private CsvSeverity currentSeverity;
        private CaseStatus status;
        private long workflowVersion;
        private Instant riskAcceptedUntil;
        private String decisionReason;
        private String decisionEvidence;
        private Instant lastWorkflowAt;
        private final String closurePolicy;

        private CaseEntry(String naturalKey, String assetKey, WazuhObservation observation) {
            publicId = publicId("case", naturalKey);
            this.assetKey = assetKey;
            assetPublicId = publicId("asset", assetKey);
            sourceProfileId = observation.sourceProfileId();
            cveId = observation.cveId();
            exposureKeys = new LinkedHashSet<>();
            firstObservedAt = observation.detectedAt();
            lastObservedAt = observation.detectedAt();
            currentSeverity = observation.severity();
            status = CaseStatus.OPEN;
            closurePolicy = observation.contractId().equals("WAZUH_CSV_V2")
                    ? "EXPLICIT_SOURCE_EVIDENCE_ONLY" : "POSITIVE_ONLY_NO_AUTO_CLOSE";
        }

        private CaseEntry(CaseEntry source) {
            publicId = source.publicId;
            assetKey = source.assetKey;
            assetPublicId = source.assetPublicId;
            sourceProfileId = source.sourceProfileId;
            cveId = source.cveId;
            exposureKeys = new LinkedHashSet<>(source.exposureKeys);
            firstObservedAt = source.firstObservedAt;
            lastObservedAt = source.lastObservedAt;
            currentSeverity = source.currentSeverity;
            status = source.status;
            workflowVersion = source.workflowVersion;
            riskAcceptedUntil = source.riskAcceptedUntil;
            decisionReason = source.decisionReason;
            decisionEvidence = source.decisionEvidence;
            lastWorkflowAt = source.lastWorkflowAt;
            closurePolicy = source.closurePolicy;
        }

        private void recompute(Map<String, ExposureEntry> exposures) {
            Instant first = null;
            Instant last = null;
            CsvSeverity severity = CsvSeverity.UNKNOWN;
            boolean anyActive = false;
            for (String exposureKey : exposureKeys) {
                ExposureEntry exposure = exposures.get(exposureKey);
                if (exposure == null) {
                    continue;
                }
                if (first == null || exposure.firstObservedAt.isBefore(first)) {
                    first = exposure.firstObservedAt;
                }
                if (last == null || exposure.lastObservedAt.isAfter(last)) {
                    last = exposure.lastObservedAt;
                }
                severity = maximumSeverity(severity, exposure.currentSeverity);
                anyActive |= exposure.findingStatus == FindingStatus.ACTIVE;
            }
            if (first != null) {
                firstObservedAt = first;
                lastObservedAt = last;
                currentSeverity = severity;
                if (status == CaseStatus.OPEN || status == CaseStatus.SOURCE_RESOLVED) {
                    status = anyActive ? CaseStatus.OPEN : CaseStatus.SOURCE_RESOLVED;
                }
            }
        }

        private Map<String, Object> toMap(AssetEntry asset, Instant now) {
            Map<String, Object> output = new LinkedHashMap<>();
            output.put("caseId", publicId);
            output.put("assetId", assetPublicId);
            output.put("assetName", asset == null ? "" : asset.observedName);
            output.put("osName", asset == null ? "" : asset.osNameRaw);
            output.put("sourceProfileId", sourceProfileId);
            output.put("cveId", cveId);
            output.put("status", status.name());
            output.put("currentSeverity", currentSeverity.name());
            output.put("firstObservedAt", firstObservedAt.toString());
            output.put("lastObservedAt", lastObservedAt.toString());
            output.put("exposureCount", exposureKeys.size());
            output.put("workflowVersion", workflowVersion);
            output.put("riskAcceptedUntil",
                    riskAcceptedUntil == null ? null : riskAcceptedUntil.toString());
            output.put("riskAcceptanceExpired", status == CaseStatus.ACCEPTED_RISK
                    && riskAcceptedUntil != null && !riskAcceptedUntil.isAfter(now));
            output.put("decisionReason", decisionReason);
            output.put("decisionEvidence", decisionEvidence);
            output.put("lastWorkflowAt", lastWorkflowAt == null ? null : lastWorkflowAt.toString());
            output.put("closurePolicy", closurePolicy);
            return output;
        }
    }

    private static final class Accumulator {
        private final UUID importId;
        private long acceptedObservations;
        private long insertedObservations;
        private long duplicateObservations;
        private final Set<String> newAssetKeys = new HashSet<>();
        private final Set<String> newVulnerabilityKeys = new HashSet<>();
        private final Set<String> newComponentKeys = new HashSet<>();
        private final Set<String> newExposureKeys = new HashSet<>();
        private final Set<String> updatedExposureKeys = new HashSet<>();
        private final Set<String> newCaseKeys = new HashSet<>();
        private final Set<String> updatedCaseKeys = new HashSet<>();
        private final Set<String> touchedCaseKeys = new HashSet<>();

        private Accumulator(UUID importId) {
            this.importId = importId;
        }

        private DomainMaterializationResult result(Instant materializedAt) {
            return new DomainMaterializationResult(
                    importId,
                    false,
                    acceptedObservations,
                    insertedObservations,
                    duplicateObservations,
                    newAssetKeys.size(),
                    newVulnerabilityKeys.size(),
                    newComponentKeys.size(),
                    newExposureKeys.size(),
                    updatedExposureKeys.size(),
                    newCaseKeys.size(),
                    updatedCaseKeys.size(),
                    materializedAt
            );
        }
    }
}
