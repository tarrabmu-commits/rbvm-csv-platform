package io.rbvm.postgres;

import io.rbvm.csv.AnalysisReport;
import io.rbvm.csv.CanonicalProjection;
import io.rbvm.csv.CsvSeverity;
import io.rbvm.csv.FindingStatus;
import io.rbvm.csv.ProjectionImport;
import io.rbvm.csv.WazuhCsvAnalyzer;
import io.rbvm.csv.WazuhObservation;
import io.rbvm.csv.VulnerabilityIntelligenceEvidence;
import io.rbvm.domain.CaseAuditEvent;
import io.rbvm.domain.CaseActionType;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Transactional PostgreSQL write projection of the local evidence journals.
 *
 * <p>This class is the synchronous write side of the Increment 6 PostgreSQL
 * runtime. An import is not marked completed until its transaction commits;
 * API reads are served by {@link PostgresReadCatalog}.</p>
 */
public final class PostgresCanonicalProjection implements CanonicalProjection {
    private static final String TENANT_KEY = "local";
    private static final long PROJECTION_LOCK = 6_416_166_340_247_368_022L;
    private static final int REQUIRED_SCHEMA_VERSION = 7;

    private final JdbcConnectionFactory connections;
    private final Clock clock;
    private final int schemaVersion;
    private volatile Instant lastSynchronizedAt;
    private volatile String lastFailure;

    public PostgresCanonicalProjection(JdbcConnectionFactory connections, boolean migrate)
            throws IOException {
        this(connections, migrate, Clock.systemUTC());
    }

    PostgresCanonicalProjection(
            JdbcConnectionFactory connections,
            boolean migrate,
            Clock clock
    ) throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        this.clock = Objects.requireNonNull(clock, "clock");
        PostgresMigrator migrator = new PostgresMigrator(connections);
        schemaVersion = migrate ? migrator.migrate() : migrator.installedVersion();
        if (schemaVersion < REQUIRED_SCHEMA_VERSION) {
            throw new IOException(
                    "PostgreSQL schema version " + schemaVersion
                            + " is older than required version " + REQUIRED_SCHEMA_VERSION);
        }
    }

    @Override
    public void synchronizeImport(ProjectionImport input) throws IOException {
        Objects.requireNonNull(input, "input");
        try (Connection connection = connections.open()) {
            beginProjectionTransaction(connection);
            try {
                Instant now = clock.instant();
                UUID tenantId = ensureTenant(connection, now);
                UUID sourceProfileId = ensureSourceProfile(
                        connection,
                        tenantId,
                        input.sourceProfileId(),
                        input.analysis().contractId(),
                        now
                );
                ensureCatalogState(connection, tenantId, now);
                if (isMaterialized(connection, tenantId, input.importId())) {
                    connection.commit();
                    synchronizedSuccessfully(now);
                    return;
                }

                upsertImportRun(connection, tenantId, sourceProfileId, input, now);
                ProjectionAccumulator accumulator = new ProjectionAccumulator(
                        tenantId,
                        sourceProfileId,
                        input,
                        now
                );
                AnalysisReport projected = new WazuhCsvAnalyzer(
                        input.sourceProfileId(), input.analysis().contractId()).analyze(
                        input.rawEvidence(),
                        0,
                        observation -> {
                            try {
                                projectObservation(connection, accumulator, observation);
                            } catch (SQLException exception) {
                                throw PostgresErrors.sanitized(
                                        "Could not project a Wazuh observation",
                                        exception
                                );
                            }
                        }
                );
                verifyAnalysis(input.analysis(), projected, accumulator);
                accumulator.parentMutations.flush(connection);
                recomputeCases(connection, tenantId, sourceProfileId, now);
                writeMaterialization(connection, accumulator, now);
                completeImportRun(connection, tenantId, input.importId(), projected, now);
                incrementCatalogRevision(connection, tenantId, now);
                connection.commit();
                synchronizedSuccessfully(now);
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                synchronizedFailure(exception);
                if (exception instanceof IOException ioException) {
                    throw ioException;
                }
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL import projection failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            synchronizedFailure(exception);
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL projection transaction",
                    exception
            );
        }
    }

    @Override
    public void synchronizeCaseEvent(CaseAuditEvent event) throws IOException {
        Objects.requireNonNull(event, "event");
        try (Connection connection = connections.open()) {
            beginProjectionTransaction(connection);
            try {
                Instant now = clock.instant();
                UUID tenantId = requireTenant(connection);
                ensureCatalogState(connection, tenantId, now);
                StoredEvent existing = findStoredEvent(
                        connection,
                        tenantId,
                        event.caseId(),
                        event.idempotencyKey()
                );
                if (existing != null) {
                    if (!existing.publicId().equals(event.eventId())
                            || !existing.requestFingerprint().equals(event.requestFingerprint())) {
                        throw new IOException(
                                "PostgreSQL case event conflicts with its Idempotency-Key");
                    }
                    connection.commit();
                    synchronizedSuccessfully(now);
                    return;
                }

                StoredCase storedCase = lockCase(connection, tenantId, event.caseId());
                if (storedCase == null) {
                    throw new IOException("PostgreSQL projection has no case " + event.caseId());
                }
                if (storedCase.workflowVersion() + 1 != event.caseVersion()) {
                    throw new IOException(
                            "PostgreSQL case workflow version mismatch for " + event.caseId());
                }
                if (!storedCase.status().equals(event.fromStatus().name())) {
                    throw new IOException(
                            "PostgreSQL case status mismatch for " + event.caseId());
                }

                insertCaseEvent(connection, tenantId, storedCase.id(), event);
                updateCaseDecision(connection, tenantId, storedCase, event);
                incrementCatalogRevision(connection, tenantId, now);
                connection.commit();
                synchronizedSuccessfully(now);
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                synchronizedFailure(exception);
                if (exception instanceof IOException ioException) {
                    throw ioException;
                }
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL case-event projection failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            synchronizedFailure(exception);
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL workflow transaction",
                    exception
            );
        }
    }

    @Override
    public Map<String, Object> health() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("backend", "POSTGRESQL");
        output.put("schemaVersion", schemaVersion);
        try (Connection connection = connections.open()) {
            UUID tenantId = optionalTenant(connection);
            long materializedImports = tenantId == null
                    ? 0
                    : scalarLong(connection,
                            "SELECT count(*) FROM rbvm.domain_materialization WHERE tenant_id = ?",
                            tenantId);
            long unreconciled = tenantId == null
                    ? 0
                    : scalarLong(connection, """
                            SELECT COALESCE(unreconciled_imports, 0)
                                 + COALESCE(unreconciled_case_workflows, 0)
                                 + COALESCE(assets_without_public_id, 0)
                                 + COALESCE(components_without_public_id, 0)
                                 + COALESCE(cases_without_public_id, 0)
                                 + COALESCE(exposures_without_public_id, 0)
                                 + COALESCE(audit_events_without_public_id, 0)
                            FROM rbvm.postgres_projection_reconciliation
                            WHERE tenant_id = ?
                            """, tenantId);
            output.put("status", unreconciled == 0 && lastFailure == null ? "UP" : "DEGRADED");
            output.put("materializedImports", materializedImports);
            output.put("reconciliationIssues", unreconciled);
            output.put("lastSynchronizedAt",
                    lastSynchronizedAt == null ? null : lastSynchronizedAt.toString());
            output.put("lastFailure", lastFailure);
        } catch (SQLException exception) {
            output.put("status", "DOWN");
            output.put("materializedImports", null);
            output.put("reconciliationIssues", null);
            output.put("lastSynchronizedAt",
                    lastSynchronizedAt == null ? null : lastSynchronizedAt.toString());
            output.put("lastFailure", concise(exception));
        }
        return output;
    }

    private static void beginProjectionTransaction(Connection connection) throws SQLException {
        connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
        connection.setAutoCommit(false);
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pg_advisory_xact_lock(?)")) {
            statement.setLong(1, PROJECTION_LOCK);
            statement.execute();
        }
    }

    private static UUID ensureTenant(Connection connection, Instant now) throws SQLException {
        UUID proposed = stableUuid("tenant", TENANT_KEY);
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.tenant(id, tenant_key, display_name, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (tenant_key) DO UPDATE SET display_name = EXCLUDED.display_name
                RETURNING id
                """)) {
            statement.setObject(1, proposed);
            statement.setString(2, TENANT_KEY);
            statement.setString(3, "Local RBVM Tenant");
            setInstant(statement, 4, now);
            return requiredUuid(statement);
        }
    }

    private static UUID requireTenant(Connection connection) throws SQLException, IOException {
        UUID tenant = optionalTenant(connection);
        if (tenant == null) {
            throw new IOException("PostgreSQL projection tenant has not been initialized");
        }
        return tenant;
    }

    private static UUID optionalTenant(Connection connection) throws SQLException {
        return selectUuid(
                connection,
                "SELECT id FROM rbvm.tenant WHERE tenant_key = ?",
                TENANT_KEY
        );
    }

    private static UUID ensureSourceProfile(
            Connection connection,
            UUID tenantId,
            String externalKey,
            String contractId,
            Instant now
    ) throws SQLException {
        UUID proposed = stableUuid("source-profile", key(TENANT_KEY, externalKey));
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.source_profile(
                    id, tenant_id, external_key, source_type, contract_id,
                    semantics, enabled, created_at
                ) VALUES (?, ?, ?, 'WAZUH_CSV', ?, ?, true, ?)
                ON CONFLICT (tenant_id, external_key)
                DO UPDATE SET enabled = true
                WHERE rbvm.source_profile.contract_id = EXCLUDED.contract_id
                RETURNING id
                """)) {
            statement.setObject(1, proposed);
            statement.setObject(2, tenantId);
            statement.setString(3, externalKey);
            statement.setString(4, contractId);
            statement.setString(5, contractId.equals("WAZUH_CSV_V2")
                    ? "EXPLICIT_FINDING_LIFECYCLE_EXPORT" : "POSITIVE_OBSERVATION_EXPORT");
            setInstant(statement, 6, now);
            UUID result = optionalUuid(statement);
            if (result == null) {
                throw new SQLException("Source profile is already bound to a different CSV contract");
            }
            return result;
        }
    }

    private static void ensureCatalogState(
            Connection connection,
            UUID tenantId,
            Instant now
    ) throws SQLException {
        executeUpdate(connection, """
                INSERT INTO rbvm.catalog_state(tenant_id, revision, updated_at)
                VALUES (?, 0, ?)
                ON CONFLICT (tenant_id) DO NOTHING
                """, tenantId, now);
    }

    private static boolean isMaterialized(
            Connection connection,
            UUID tenantId,
            UUID importId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT 1 FROM rbvm.domain_materialization
                WHERE tenant_id = ? AND import_id = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, importId);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next();
            }
        }
    }

    private static void upsertImportRun(
            Connection connection,
            UUID tenantId,
            UUID sourceProfileId,
            ProjectionImport input,
            Instant now
    ) throws SQLException {
        AnalysisReport analysis = input.analysis();
        executeUpdate(connection, """
                INSERT INTO rbvm.import_run(
                    id, tenant_id, source_profile_id, status, contract_id, semantics,
                    commit_scope, file_sha256, file_size_bytes, raw_evidence_uri,
                    logical_rows, accepted_rows, deduplicated_rows, quarantined_rows,
                    created_at, confirmed_at
                ) VALUES (?, ?, ?, 'IMPORTING', ?, ?, 'CANONICAL_DOMAIN_AND_RAW_EVIDENCE',
                    ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET
                    status = 'IMPORTING',
                    logical_rows = EXCLUDED.logical_rows,
                    accepted_rows = EXCLUDED.accepted_rows,
                    deduplicated_rows = EXCLUDED.deduplicated_rows,
                    quarantined_rows = EXCLUDED.quarantined_rows,
                    confirmed_at = EXCLUDED.confirmed_at
                """,
                input.importId(),
                tenantId,
                sourceProfileId,
                analysis.contractId(),
                analysis.semantics(),
                analysis.fileSha256(),
                analysis.fileSizeBytes(),
                input.rawEvidence().toAbsolutePath().normalize().toUri().toString(),
                analysis.logicalRows(),
                analysis.acceptedRows(),
                analysis.deduplicatedRows(),
                analysis.quarantinedRows(),
                input.createdAt(),
                now
        );
    }

    private static void projectObservation(
            Connection connection,
            ProjectionAccumulator accumulator,
            WazuhObservation observation
    ) throws SQLException {
        accumulator.acceptedObservations++;
        EntityRef asset = ensureAsset(connection, accumulator, observation);
        EntityRef vulnerability = ensureVulnerability(connection, accumulator, observation);
        EntityRef component = ensureComponent(connection, accumulator, asset, observation);
        UUID observationId = insertObservation(
                connection,
                accumulator,
                observation,
                asset.id(),
                vulnerability.id(),
                component.id()
        );
        if (observationId == null) {
            observationId = selectUuid(connection, """
                    SELECT id FROM rbvm.observation
                    WHERE tenant_id = ? AND source_profile_id = ? AND fingerprint = ?
                    """, accumulator.tenantId, accumulator.sourceProfileId,
                    observation.observationFingerprint());
            if (observationId == null) {
                throw new SQLException("Observation conflict did not resolve to an existing row");
            }
            accumulator.duplicateObservations++;
            linkImportObservation(connection, accumulator, observation, observationId);
            return;
        }

        accumulator.insertedObservations++;
        linkImportObservation(connection, accumulator, observation, observationId);
        insertObservationReferences(connection, accumulator.tenantId, observationId,
                observation.referencesRaw());
        EntityRef caseRef = ensureCase(
                connection,
                accumulator,
                asset,
                vulnerability,
                observation
        );
        EntityRef exposure = ensureExposure(
                connection,
                accumulator,
                caseRef,
                asset,
                vulnerability,
                component,
                observation
        );
        executeUpdate(connection, """
                INSERT INTO rbvm.exposure_observation(tenant_id, exposure_id, observation_id)
                VALUES (?, ?, ?)
                ON CONFLICT DO NOTHING
                """, accumulator.tenantId, exposure.id(), observationId);
    }

    private static EntityRef ensureAsset(
            Connection connection,
            ProjectionAccumulator accumulator,
            WazuhObservation observation
    ) throws SQLException {
        String naturalKey = key(
                TENANT_KEY,
                observation.sourceProfileId(),
                observation.agentIdentityKey()
        );
        EntityRef cached = accumulator.assets.get(naturalKey);
        boolean createdThisCall = false;
        if (cached == null) {
            String publicId = publicId("asset", naturalKey);
            UUID proposed = stableUuid("asset", naturalKey);
            UUID inserted = returningUuid(connection, """
                    INSERT INTO rbvm.asset(
                        id, tenant_id, source_profile_id, public_id, observed_name,
                        normalized_observed_name, os_name_raw, identity_basis,
                        identity_confidence, source_asset_id, first_observed_at, last_observed_at,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (tenant_id, source_profile_id, normalized_observed_name)
                    DO NOTHING RETURNING id
                    """,
                    proposed,
                    accumulator.tenantId,
                    accumulator.sourceProfileId,
                    publicId,
                    observation.agentObservedName(),
                    observation.agentIdentityKey(),
                    observation.osNameRaw(),
                    observation.agentSourceId().isBlank() ? "SOURCE_NAME_ONLY" : "SOURCE_STABLE_ID",
                    observation.agentSourceId().isBlank() ? "LOW" : "HIGH",
                    observation.agentSourceId().isBlank() ? null : observation.agentSourceId(),
                    observation.detectedAt(),
                    observation.detectedAt(),
                    accumulator.now,
                    accumulator.now
            );
            boolean isNew = inserted != null;
            UUID id = isNew ? inserted : selectUuid(connection, """
                    SELECT id FROM rbvm.asset
                    WHERE tenant_id = ? AND source_profile_id = ?
                      AND normalized_observed_name = ?
                    """, accumulator.tenantId, accumulator.sourceProfileId,
                    observation.agentIdentityKey());
            cached = new EntityRef(required(id, "asset"), publicId);
            accumulator.assets.put(naturalKey, cached);
            if (isNew) {
                accumulator.newAssets++;
                createdThisCall = true;
            }
        }
        accumulator.parentMutations.observeAsset(
                cached.id(), cached.publicId(), createdThisCall, observation);
        return cached;
    }

    private static EntityRef ensureVulnerability(
            Connection connection,
            ProjectionAccumulator accumulator,
            WazuhObservation observation
    ) throws SQLException {
        EntityRef cached = accumulator.vulnerabilities.get(observation.cveId());
        boolean createdThisCall = false;
        if (cached == null) {
            UUID proposed = stableUuid("vulnerability", observation.cveId());
            UUID inserted = returningUuid(connection, """
                    INSERT INTO rbvm.vulnerability(
                        id, cve_id, created_at, description_current, description_observed_at,
                        cvss_version, cvss_base_score, cvss_vector, epss_probability,
                        epss_percentile, known_exploited, kev_date_added, kev_due_date,
                        intelligence_observed_at, intelligence_source_references, priority_tier
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (cve_id) DO NOTHING RETURNING id
                    """,
                    proposed,
                    observation.cveId(),
                    accumulator.now,
                    observation.descriptionSnapshot(),
                    observation.detectedAt(),
                    intel(observation, VulnerabilityIntelligenceEvidence::cvssVersion),
                    intel(observation, VulnerabilityIntelligenceEvidence::cvssBaseScore),
                    intel(observation, VulnerabilityIntelligenceEvidence::cvssVector),
                    intel(observation, VulnerabilityIntelligenceEvidence::epssProbability),
                    intel(observation, VulnerabilityIntelligenceEvidence::epssPercentile),
                    intel(observation, VulnerabilityIntelligenceEvidence::knownExploited),
                    intel(observation, VulnerabilityIntelligenceEvidence::kevDateAdded),
                    intel(observation, VulnerabilityIntelligenceEvidence::kevDueDate),
                    intel(observation, VulnerabilityIntelligenceEvidence::observedAt),
                    intel(observation, VulnerabilityIntelligenceEvidence::sourceReferences),
                    observation.intelligence() == null ? "UNENRICHED"
                            : observation.intelligence().priorityTier()
            );
            boolean isNew = inserted != null;
            UUID id = isNew ? inserted : selectUuid(
                    connection,
                    "SELECT id FROM rbvm.vulnerability WHERE cve_id = ?",
                    observation.cveId()
            );
            cached = new EntityRef(required(id, "vulnerability"), null);
            accumulator.vulnerabilities.put(observation.cveId(), cached);
            if (isNew) {
                accumulator.newVulnerabilities++;
                createdThisCall = true;
            }
        }
        accumulator.parentMutations.observeVulnerability(
                cached.id(), createdThisCall, observation);
        return cached;
    }

    private static EntityRef ensureComponent(
            Connection connection,
            ProjectionAccumulator accumulator,
            EntityRef asset,
            WazuhObservation observation
    ) throws SQLException {
        String naturalKey = key(
                key(TENANT_KEY, observation.sourceProfileId(), observation.agentIdentityKey()),
                observation.affectedProductIdentityKey()
        );
        EntityRef cached = accumulator.components.get(naturalKey);
        boolean createdThisCall = false;
        if (cached == null) {
            String publicId = publicId("component", naturalKey);
            UUID proposed = stableUuid("component", naturalKey);
            UUID inserted = returningUuid(connection, """
                    INSERT INTO rbvm.asset_component(
                        id, tenant_id, asset_id, public_id, observed_product_name,
                        normalized_product_name, version_status, first_observed_at,
                        last_observed_at, created_at, updated_at, package_version,
                        package_architecture
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (tenant_id, asset_id, normalized_product_name)
                    DO NOTHING RETURNING id
                    """,
                    proposed,
                    accumulator.tenantId,
                    asset.id(),
                    publicId,
                    observation.affectedProductObservedName(),
                    observation.affectedProductIdentityKey(),
                    observation.packageVersion().isBlank()
                            ? "UNKNOWN_FROM_SOURCE" : "OBSERVED_FROM_SOURCE",
                    observation.detectedAt(),
                    observation.detectedAt(),
                    accumulator.now,
                    accumulator.now,
                    observation.packageVersion(),
                    observation.packageArchitecture()
            );
            boolean isNew = inserted != null;
            UUID id = isNew ? inserted : selectUuid(connection, """
                    SELECT id FROM rbvm.asset_component
                    WHERE tenant_id = ? AND asset_id = ? AND normalized_product_name = ?
                    """, accumulator.tenantId, asset.id(),
                    observation.affectedProductIdentityKey());
            cached = new EntityRef(required(id, "component"), publicId);
            accumulator.components.put(naturalKey, cached);
            if (isNew) {
                accumulator.newComponents++;
                createdThisCall = true;
            }
        }
        if (!createdThisCall) {
            executeUpdate(connection, """
                    UPDATE rbvm.asset_component SET
                        public_id = ?,
                        first_observed_at = LEAST(first_observed_at, ?),
                        observed_product_name = CASE
                            WHEN ? > last_observed_at THEN ? ELSE observed_product_name END,
                        package_version = CASE
                            WHEN ? > last_observed_at THEN ? ELSE package_version END,
                        package_architecture = CASE
                            WHEN ? > last_observed_at THEN ? ELSE package_architecture END,
                        last_observed_at = GREATEST(last_observed_at, ?),
                        updated_at = ?
                    WHERE tenant_id = ? AND id = ?
                    """,
                    cached.publicId(),
                    observation.detectedAt(),
                    observation.detectedAt(),
                    observation.affectedProductObservedName(),
                    observation.detectedAt(),
                    observation.packageVersion(),
                    observation.detectedAt(),
                    observation.packageArchitecture(),
                    observation.detectedAt(),
                    accumulator.now,
                    accumulator.tenantId,
                    cached.id()
            );
        }
        return cached;
    }

    private static UUID insertObservation(
            Connection connection,
            ProjectionAccumulator accumulator,
            WazuhObservation observation,
            UUID assetId,
            UUID vulnerabilityId,
            UUID componentId
    ) throws SQLException {
        String naturalKey = key(
                TENANT_KEY,
                observation.sourceProfileId(),
                observation.observationFingerprint()
        );
        return returningUuid(connection, """
                INSERT INTO rbvm.observation(
                    id, tenant_id, source_profile_id, asset_id, vulnerability_id,
                    component_id, fingerprint, severity, source_severity_recognized,
                    description_snapshot, references_raw, os_name_raw, detected_at,
                    first_ingested_at, finding_status, resolved_at
                    , cvss_version_snapshot, cvss_base_score_snapshot, cvss_vector_snapshot,
                    epss_probability_snapshot, epss_percentile_snapshot,
                    known_exploited_snapshot, kev_date_added_snapshot, kev_due_date_snapshot,
                    intelligence_observed_at_snapshot,
                    intelligence_source_references_snapshot
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, source_profile_id, fingerprint)
                DO NOTHING RETURNING id
                """,
                stableUuid("observation", naturalKey),
                accumulator.tenantId,
                accumulator.sourceProfileId,
                assetId,
                vulnerabilityId,
                componentId,
                observation.observationFingerprint(),
                observation.severity().name(),
                observation.sourceSeverityRecognized(),
                observation.descriptionSnapshot(),
                observation.referencesRaw(),
                observation.osNameRaw(),
                observation.detectedAt(),
                accumulator.now,
                observation.findingStatus().name(),
                observation.resolvedAt(),
                intel(observation, VulnerabilityIntelligenceEvidence::cvssVersion),
                intel(observation, VulnerabilityIntelligenceEvidence::cvssBaseScore),
                intel(observation, VulnerabilityIntelligenceEvidence::cvssVector),
                intel(observation, VulnerabilityIntelligenceEvidence::epssProbability),
                intel(observation, VulnerabilityIntelligenceEvidence::epssPercentile),
                intel(observation, VulnerabilityIntelligenceEvidence::knownExploited),
                intel(observation, VulnerabilityIntelligenceEvidence::kevDateAdded),
                intel(observation, VulnerabilityIntelligenceEvidence::kevDueDate),
                intel(observation, VulnerabilityIntelligenceEvidence::observedAt),
                intel(observation, VulnerabilityIntelligenceEvidence::sourceReferences)
        );
    }

    private static <T> T intel(
            WazuhObservation observation,
            java.util.function.Function<VulnerabilityIntelligenceEvidence, T> getter
    ) {
        return observation.intelligence() == null ? null : getter.apply(observation.intelligence());
    }

    private static void linkImportObservation(
            Connection connection,
            ProjectionAccumulator accumulator,
            WazuhObservation observation,
            UUID observationId
    ) throws SQLException {
        executeUpdate(connection, """
                INSERT INTO rbvm.import_observation(
                    tenant_id, import_id, observation_id, source_row_number, linked_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                accumulator.tenantId,
                accumulator.input.importId(),
                observationId,
                observation.sourceRowNumber(),
                accumulator.now
        );
    }

    private static void insertObservationReferences(
            Connection connection,
            UUID tenantId,
            UUID observationId,
            String referencesRaw
    ) throws SQLException {
        int ordinal = 0;
        for (String reference : splitReferences(referencesRaw)) {
            executeUpdate(connection, """
                    INSERT INTO rbvm.observation_reference(
                        tenant_id, observation_id, ordinal, reference_uri, is_http
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """, tenantId, observationId, ordinal, reference, isHttp(reference));
            ordinal++;
        }
    }

    private static EntityRef ensureCase(
            Connection connection,
            ProjectionAccumulator accumulator,
            EntityRef asset,
            EntityRef vulnerability,
            WazuhObservation observation
    ) throws SQLException {
        String naturalKey = key(
                TENANT_KEY,
                observation.sourceProfileId(),
                observation.agentIdentityKey(),
                observation.cveId()
        );
        EntityRef cached = accumulator.cases.get(naturalKey);
        if (cached == null) {
            String publicId = publicId("case", naturalKey);
            UUID proposed = stableUuid("case", naturalKey);
            UUID inserted = returningUuid(connection, """
                    INSERT INTO rbvm.vulnerability_case(
                        id, tenant_id, source_profile_id, asset_id, vulnerability_id,
                        public_id, status, closure_policy, current_severity,
                        first_observed_at, last_observed_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?,
                              ?, ?, ?, ?, ?)
                    ON CONFLICT (tenant_id, source_profile_id, asset_id, vulnerability_id)
                    DO NOTHING RETURNING id
                    """,
                    proposed,
                    accumulator.tenantId,
                    accumulator.sourceProfileId,
                    asset.id(),
                    vulnerability.id(),
                    publicId,
                    observation.contractId().equals("WAZUH_CSV_V2")
                            ? "EXPLICIT_SOURCE_EVIDENCE_ONLY" : "POSITIVE_ONLY_NO_AUTO_CLOSE",
                    observation.severity().name(),
                    observation.detectedAt(),
                    observation.detectedAt(),
                    accumulator.now,
                    accumulator.now
            );
            boolean isNew = inserted != null;
            UUID id = isNew ? inserted : selectUuid(connection, """
                    SELECT id FROM rbvm.vulnerability_case
                    WHERE tenant_id = ? AND source_profile_id = ?
                      AND asset_id = ? AND vulnerability_id = ?
                    """, accumulator.tenantId, accumulator.sourceProfileId,
                    asset.id(), vulnerability.id());
            cached = new EntityRef(required(id, "case"), publicId);
            accumulator.cases.put(naturalKey, cached);
            if (isNew) {
                accumulator.newCases++;
            } else {
                accumulator.updatedCaseIds.add(cached.id());
                executeUpdate(connection, """
                        UPDATE rbvm.vulnerability_case SET public_id = ?, updated_at = ?
                        WHERE tenant_id = ? AND id = ?
                        """, cached.publicId(), accumulator.now,
                        accumulator.tenantId, cached.id());
            }
        }
        return cached;
    }

    private static EntityRef ensureExposure(
            Connection connection,
            ProjectionAccumulator accumulator,
            EntityRef caseRef,
            EntityRef asset,
            EntityRef vulnerability,
            EntityRef component,
            WazuhObservation observation
    ) throws SQLException {
        String caseNaturalKey = key(
                TENANT_KEY,
                observation.sourceProfileId(),
                observation.agentIdentityKey(),
                observation.cveId()
        );
        String naturalKey = key(caseNaturalKey, observation.affectedProductIdentityKey());
        EntityRef cached = accumulator.exposures.get(naturalKey);
        boolean createdThisCall = false;
        if (cached == null) {
            String publicId = publicId("exposure", naturalKey);
            UUID proposed = stableUuid("exposure", naturalKey);
            UUID inserted = returningUuid(connection, """
                    INSERT INTO rbvm.exposure(
                        id, tenant_id, source_profile_id, case_id, asset_id,
                        vulnerability_id, component_id, public_id, status, closure_policy,
                        current_severity, current_severity_observed_at, first_observed_at,
                        last_observed_at, observation_count, severity_changed,
                        timestamp_severity_conflict, created_at, updated_at,
                        lifecycle_observed_at, resolved_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, false,
                              false, ?, ?, ?, ?)
                    ON CONFLICT (
                        tenant_id, source_profile_id, asset_id, vulnerability_id, component_id
                    ) DO NOTHING RETURNING id
                    """,
                    proposed,
                    accumulator.tenantId,
                    accumulator.sourceProfileId,
                    caseRef.id(),
                    asset.id(),
                    vulnerability.id(),
                    component.id(),
                    publicId,
                    observation.findingStatus().name(),
                    observation.contractId().equals("WAZUH_CSV_V2")
                            ? "EXPLICIT_SOURCE_EVIDENCE_ONLY" : "POSITIVE_ONLY_NO_AUTO_CLOSE",
                    observation.severity().name(),
                    observation.detectedAt(),
                    observation.detectedAt(),
                    observation.evidenceAt(),
                    accumulator.now,
                    accumulator.now,
                    observation.evidenceAt(),
                    observation.resolvedAt()
            );
            boolean isNew = inserted != null;
            UUID id = isNew ? inserted : selectUuid(connection, """
                    SELECT id FROM rbvm.exposure
                    WHERE tenant_id = ? AND source_profile_id = ? AND asset_id = ?
                      AND vulnerability_id = ? AND component_id = ?
                    """, accumulator.tenantId, accumulator.sourceProfileId,
                    asset.id(), vulnerability.id(), component.id());
            cached = new EntityRef(required(id, "exposure"), publicId);
            accumulator.exposures.put(naturalKey, cached);
            if (isNew) {
                accumulator.newExposures++;
                createdThisCall = true;
            } else {
                accumulator.updatedExposureIds.add(cached.id());
            }
        }
        if (!createdThisCall) {
            updateExistingExposure(connection, accumulator, cached, observation);
        }
        return cached;
    }

    private static void updateExistingExposure(
            Connection connection,
            ProjectionAccumulator accumulator,
            EntityRef exposure,
            WazuhObservation observation
    ) throws SQLException {
        ExposureState state;
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT current_severity, current_severity_observed_at,
                       severity_changed, timestamp_severity_conflict, status,
                       lifecycle_observed_at, resolved_at
                FROM rbvm.exposure
                WHERE tenant_id = ? AND id = ?
                FOR UPDATE
                """)) {
            statement.setObject(1, accumulator.tenantId);
            statement.setObject(2, exposure.id());
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new SQLException("Exposure disappeared during projection");
                }
                state = new ExposureState(
                        CsvSeverity.valueOf(rows.getString(1)),
                        rows.getTimestamp(2).toInstant(),
                        rows.getBoolean(3),
                        rows.getBoolean(4),
                        FindingStatus.valueOf(rows.getString(5)),
                        rows.getTimestamp(6).toInstant(),
                        rows.getTimestamp(7) == null ? null : rows.getTimestamp(7).toInstant()
                );
            }
        }

        CsvSeverity severity = state.severity();
        Instant severityAt = state.severityObservedAt();
        boolean conflict = state.timestampConflict();
        int order = observation.detectedAt().compareTo(severityAt);
        if (order > 0) {
            severity = observation.severity();
            severityAt = observation.detectedAt();
        } else if (order == 0 && observation.severity() != severity) {
            conflict = true;
            severity = maximumSeverity(severity, observation.severity());
        }
        boolean changed = state.severityChanged() || state.severity() != observation.severity();
        FindingStatus findingStatus = state.findingStatus();
        Instant lifecycleAt = state.lifecycleObservedAt();
        Instant resolvedAt = state.resolvedAt();
        int lifecycleOrder = observation.evidenceAt().compareTo(lifecycleAt);
        if (lifecycleOrder > 0 || (lifecycleOrder == 0
                && observation.findingStatus() == FindingStatus.ACTIVE)) {
            findingStatus = observation.findingStatus();
            lifecycleAt = observation.evidenceAt();
            resolvedAt = observation.resolvedAt();
        }
        executeUpdate(connection, """
                UPDATE rbvm.exposure SET
                    public_id = ?,
                    current_severity = ?,
                    current_severity_observed_at = ?,
                    first_observed_at = LEAST(first_observed_at, ?),
                    last_observed_at = GREATEST(last_observed_at, ?),
                    observation_count = observation_count + 1,
                    severity_changed = ?,
                    timestamp_severity_conflict = ?,
                    status = ?,
                    lifecycle_observed_at = ?,
                    resolved_at = ?,
                    updated_at = ?
                WHERE tenant_id = ? AND id = ?
                """,
                exposure.publicId(),
                severity.name(),
                severityAt,
                observation.detectedAt(),
                observation.evidenceAt(),
                changed,
                conflict,
                findingStatus.name(),
                lifecycleAt,
                resolvedAt,
                accumulator.now,
                accumulator.tenantId,
                exposure.id()
        );
    }

    private static void recomputeCases(
            Connection connection,
            UUID tenantId,
            UUID sourceProfileId,
            Instant now
    ) throws SQLException {
        executeUpdate(connection, """
                WITH aggregates AS (
                    SELECT
                        case_id,
                        min(first_observed_at) AS first_observed_at,
                        max(last_observed_at) AS last_observed_at,
                        bool_or(status = 'ACTIVE') AS has_active,
                        max(CASE current_severity
                            WHEN 'CRITICAL' THEN 5
                            WHEN 'HIGH' THEN 4
                            WHEN 'MEDIUM' THEN 3
                            WHEN 'LOW' THEN 2
                            ELSE 1 END) AS severity_rank
                    FROM rbvm.exposure
                    WHERE tenant_id = ? AND source_profile_id = ?
                    GROUP BY case_id
                )
                UPDATE rbvm.vulnerability_case c SET
                    first_observed_at = a.first_observed_at,
                    last_observed_at = a.last_observed_at,
                    current_severity = CASE a.severity_rank
                        WHEN 5 THEN 'CRITICAL'
                        WHEN 4 THEN 'HIGH'
                        WHEN 3 THEN 'MEDIUM'
                        WHEN 2 THEN 'LOW'
                        ELSE 'UNKNOWN' END,
                    status = CASE
                        WHEN c.status NOT IN ('OPEN', 'SOURCE_RESOLVED') THEN c.status
                        WHEN a.has_active THEN 'OPEN'
                        ELSE 'SOURCE_RESOLVED' END,
                    closure_policy = CASE
                        WHEN c.closure_policy = 'EXPLICIT_SOURCE_EVIDENCE_ONLY'
                        THEN c.closure_policy ELSE 'POSITIVE_ONLY_NO_AUTO_CLOSE' END,
                    updated_at = ?
                FROM aggregates a
                WHERE c.tenant_id = ? AND c.id = a.case_id
                """, tenantId, sourceProfileId, now, tenantId);
    }

    private static void verifyAnalysis(
            AnalysisReport expected,
            AnalysisReport projected,
            ProjectionAccumulator accumulator
    ) throws IOException {
        if (!expected.fileSha256().equals(projected.fileSha256())
                || expected.acceptedRows() != projected.acceptedRows()
                || projected.acceptedRows() != accumulator.acceptedObservations
                || accumulator.acceptedObservations
                != accumulator.insertedObservations + accumulator.duplicateObservations) {
            throw new IOException("Local analysis and PostgreSQL projection ledger diverged");
        }
    }

    private static void writeMaterialization(
            Connection connection,
            ProjectionAccumulator accumulator,
            Instant materializedAt
    ) throws SQLException {
        executeUpdate(connection, """
                INSERT INTO rbvm.domain_materialization(
                    tenant_id, import_id, accepted_observations, inserted_observations,
                    duplicate_observations, new_assets, new_vulnerabilities,
                    new_components, new_exposures, updated_exposures, new_cases,
                    updated_cases, materialized_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                accumulator.tenantId,
                accumulator.input.importId(),
                accumulator.acceptedObservations,
                accumulator.insertedObservations,
                accumulator.duplicateObservations,
                accumulator.newAssets,
                accumulator.newVulnerabilities,
                accumulator.newComponents,
                accumulator.newExposures,
                (long) accumulator.updatedExposureIds.size(),
                accumulator.newCases,
                (long) accumulator.updatedCaseIds.size(),
                materializedAt
        );
    }

    private static void completeImportRun(
            Connection connection,
            UUID tenantId,
            UUID importId,
            AnalysisReport analysis,
            Instant now
    ) throws SQLException {
        int updated = executeUpdate(connection, """
                UPDATE rbvm.import_run SET
                    status = 'COMPLETED',
                    logical_rows = ?,
                    accepted_rows = ?,
                    deduplicated_rows = ?,
                    quarantined_rows = ?,
                    materialized_at = ?
                WHERE tenant_id = ? AND id = ?
                """,
                analysis.logicalRows(),
                analysis.acceptedRows(),
                analysis.deduplicatedRows(),
                analysis.quarantinedRows(),
                now,
                tenantId,
                importId
        );
        if (updated != 1) {
            throw new SQLException("Import run was not completed in PostgreSQL");
        }
    }

    private static StoredEvent findStoredEvent(
            Connection connection,
            UUID tenantId,
            String casePublicId,
            String idempotencyKey
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.public_id, e.request_sha256
                FROM rbvm.case_audit_event e
                JOIN rbvm.vulnerability_case c
                  ON c.tenant_id = e.tenant_id AND c.id = e.case_id
                WHERE e.tenant_id = ? AND c.public_id = ? AND e.idempotency_key = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, casePublicId);
            statement.setString(3, idempotencyKey);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next()
                        ? new StoredEvent(rows.getString(1).trim(), rows.getString(2).trim())
                        : null;
            }
        }
    }

    private static StoredCase lockCase(
            Connection connection,
            UUID tenantId,
            String casePublicId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, status, workflow_version, risk_accepted_until,
                       decision_reason, decision_evidence
                FROM rbvm.vulnerability_case
                WHERE tenant_id = ? AND public_id = ?
                FOR UPDATE
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, casePublicId);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return null;
                }
                Timestamp acceptedUntil = rows.getTimestamp(4);
                return new StoredCase(
                        rows.getObject(1, UUID.class),
                        rows.getString(2),
                        rows.getLong(3),
                        acceptedUntil == null ? null : acceptedUntil.toInstant(),
                        rows.getString(5),
                        rows.getString(6)
                );
            }
        }
    }

    private static void insertCaseEvent(
            Connection connection,
            UUID tenantId,
            UUID caseId,
            CaseAuditEvent event
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO rbvm.case_audit_event(
                    id, tenant_id, case_id, case_version, idempotency_key,
                    request_sha256, action_type, from_status, to_status, reason,
                    expires_at, evidence_reference, actor_id, actor_assurance,
                    occurred_at, public_id, source_sequence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, stableUuid("case-event", event.eventId()));
            statement.setObject(2, tenantId);
            statement.setObject(3, caseId);
            statement.setLong(4, event.caseVersion());
            statement.setString(5, event.idempotencyKey());
            statement.setString(6, event.requestFingerprint());
            statement.setString(7, event.action().name());
            statement.setString(8, event.fromStatus().name());
            statement.setString(9, event.toStatus().name());
            statement.setString(10, event.reason());
            setNullableInstant(statement, 11, event.expiresAt());
            setNullableString(statement, 12, event.evidenceReference());
            statement.setString(13, event.actorId());
            statement.setString(14, event.actorAssurance());
            setInstant(statement, 15, event.occurredAt());
            statement.setString(16, event.eventId());
            statement.setLong(17, event.sequence());
            statement.executeUpdate();
        }
    }

    private static void updateCaseDecision(
            Connection connection,
            UUID tenantId,
            StoredCase current,
            CaseAuditEvent event
    ) throws SQLException {
        Instant acceptedUntil = current.riskAcceptedUntil();
        String reason = current.decisionReason();
        String evidence = current.decisionEvidence();
        if (event.action() == CaseActionType.ACCEPT_RISK) {
            acceptedUntil = event.expiresAt();
            reason = event.reason();
            evidence = event.evidenceReference();
        } else if (event.action() == CaseActionType.MARK_FALSE_POSITIVE
                || event.action() == CaseActionType.CLOSE_MANUAL) {
            acceptedUntil = null;
            reason = event.reason();
            evidence = event.evidenceReference();
        } else if (event.action() == CaseActionType.REOPEN) {
            acceptedUntil = null;
            reason = null;
            evidence = null;
        }

        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE rbvm.vulnerability_case SET
                    status = ?, workflow_version = ?, risk_accepted_until = ?,
                    decision_reason = ?, decision_evidence = ?, last_workflow_at = ?,
                    updated_at = ?
                WHERE tenant_id = ? AND id = ?
                """)) {
            statement.setString(1, event.toStatus().name());
            statement.setLong(2, event.caseVersion());
            setNullableInstant(statement, 3, acceptedUntil);
            setNullableString(statement, 4, reason);
            setNullableString(statement, 5, evidence);
            setInstant(statement, 6, event.occurredAt());
            setInstant(statement, 7, event.occurredAt());
            statement.setObject(8, tenantId);
            statement.setObject(9, current.id());
            if (statement.executeUpdate() != 1) {
                throw new SQLException("PostgreSQL case decision update affected no row");
            }
        }
    }

    private static void incrementCatalogRevision(
            Connection connection,
            UUID tenantId,
            Instant now
    ) throws SQLException {
        int updated = executeUpdate(connection, """
                UPDATE rbvm.catalog_state
                SET revision = revision + 1, updated_at = ?
                WHERE tenant_id = ?
                """, now, tenantId);
        if (updated != 1) {
            throw new SQLException("PostgreSQL catalog revision was not incremented");
        }
    }

    private static long scalarLong(
            Connection connection,
            String sql,
            Object... parameters
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            bind(statement, parameters);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getLong(1) : 0;
            }
        }
    }

    private static UUID selectUuid(
            Connection connection,
            String sql,
            Object... parameters
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            bind(statement, parameters);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getObject(1, UUID.class) : null;
            }
        }
    }

    private static UUID returningUuid(
            Connection connection,
            String sql,
            Object... parameters
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            bind(statement, parameters);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getObject(1, UUID.class) : null;
            }
        }
    }

    private static int executeUpdate(
            Connection connection,
            String sql,
            Object... parameters
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            bind(statement, parameters);
            return statement.executeUpdate();
        }
    }

    private static UUID requiredUuid(PreparedStatement statement) throws SQLException {
        try (ResultSet rows = statement.executeQuery()) {
            if (!rows.next()) {
                throw new SQLException("PostgreSQL statement returned no identifier");
            }
            return rows.getObject(1, UUID.class);
        }
    }

    private static UUID optionalUuid(PreparedStatement statement) throws SQLException {
        try (ResultSet rows = statement.executeQuery()) {
            return rows.next() ? rows.getObject(1, UUID.class) : null;
        }
    }

    private static UUID required(UUID value, String entity) throws SQLException {
        if (value == null) {
            throw new SQLException("Could not resolve PostgreSQL " + entity + " identifier");
        }
        return value;
    }

    private static void bind(PreparedStatement statement, Object... parameters) throws SQLException {
        for (int index = 0; index < parameters.length; index++) {
            Object value = parameters[index];
            int parameter = index + 1;
            if (value instanceof Instant instant) {
                setInstant(statement, parameter, instant);
            } else {
                statement.setObject(parameter, value);
            }
        }
    }

    private static void setInstant(PreparedStatement statement, int index, Instant value)
            throws SQLException {
        statement.setTimestamp(index, Timestamp.from(value));
    }

    private static void setNullableInstant(PreparedStatement statement, int index, Instant value)
            throws SQLException {
        if (value == null) {
            statement.setNull(index, Types.TIMESTAMP_WITH_TIMEZONE);
        } else {
            setInstant(statement, index, value);
        }
    }

    private static void setNullableString(PreparedStatement statement, int index, String value)
            throws SQLException {
        if (value == null) {
            statement.setNull(index, Types.VARCHAR);
        } else {
            statement.setString(index, value);
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(PostgresErrors.sanitized(
                    "PostgreSQL rollback failed",
                    rollbackFailure
            ));
        }
    }

    private void synchronizedSuccessfully(Instant at) {
        lastSynchronizedAt = at;
        lastFailure = null;
    }

    private void synchronizedFailure(Exception exception) {
        lastFailure = concise(exception);
    }

    private static String concise(Exception exception) {
        if (exception instanceof SQLException sqlException) {
            return PostgresErrors.safeMessage(sqlException);
        }
        String message = exception.getMessage();
        return message == null || message.isBlank()
                ? exception.getClass().getSimpleName()
                : message;
    }

    private static List<String> splitReferences(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        List<String> output = new ArrayList<>();
        for (String token : raw.split(",\\s*")) {
            String value = token.trim();
            if (!value.isEmpty()) {
                output.add(value);
            }
        }
        return output;
    }

    private static boolean isHttp(String value) {
        try {
            String scheme = URI.create(value).getScheme();
            return "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static CsvSeverity maximumSeverity(CsvSeverity left, CsvSeverity right) {
        return severityRank(left) >= severityRank(right) ? left : right;
    }

    private static int severityRank(CsvSeverity severity) {
        return switch (severity) {
            case CRITICAL -> 5;
            case HIGH -> 4;
            case MEDIUM -> 3;
            case LOW -> 2;
            case UNKNOWN -> 1;
        };
    }

    private static String key(String... values) {
        return String.join("\u001F", values);
    }

    private static String publicId(String namespace, String naturalKey) {
        MessageDigest digest = sha256Digest();
        updateDigest(digest, namespace);
        updateDigest(digest, naturalKey);
        return HexFormat.of().formatHex(digest.digest());
    }

    private static UUID stableUuid(String namespace, String naturalKey) {
        MessageDigest digest = sha256Digest();
        updateDigest(digest, namespace);
        updateDigest(digest, naturalKey);
        byte[] bytes = digest.digest();
        bytes[6] = (byte) ((bytes[6] & 0x0f) | 0x50);
        bytes[8] = (byte) ((bytes[8] & 0x3f) | 0x80);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }

    private static void updateDigest(MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
        digest.update(bytes);
    }

    private static final class ProjectionAccumulator {
        private final UUID tenantId;
        private final UUID sourceProfileId;
        private final ProjectionImport input;
        private final Instant now;
        private final PostgresCanonicalProjectionMutationBuffer parentMutations;
        private final Map<String, EntityRef> assets = new HashMap<>();
        private final Map<String, EntityRef> vulnerabilities = new HashMap<>();
        private final Map<String, EntityRef> components = new HashMap<>();
        private final Map<String, EntityRef> cases = new HashMap<>();
        private final Map<String, EntityRef> exposures = new HashMap<>();
        private final Set<UUID> updatedCaseIds = new HashSet<>();
        private final Set<UUID> updatedExposureIds = new HashSet<>();
        private long acceptedObservations;
        private long insertedObservations;
        private long duplicateObservations;
        private long newAssets;
        private long newVulnerabilities;
        private long newComponents;
        private long newExposures;
        private long newCases;

        private ProjectionAccumulator(
                UUID tenantId,
                UUID sourceProfileId,
                ProjectionImport input,
                Instant now
        ) {
            this.tenantId = tenantId;
            this.sourceProfileId = sourceProfileId;
            this.input = input;
            this.now = now;
            this.parentMutations = new PostgresCanonicalProjectionMutationBuffer(tenantId, now);
        }
    }

    private record EntityRef(UUID id, String publicId) {
    }

    private record ExposureState(
            CsvSeverity severity,
            Instant severityObservedAt,
            boolean severityChanged,
            boolean timestampConflict,
            FindingStatus findingStatus,
            Instant lifecycleObservedAt,
            Instant resolvedAt
    ) {
    }

    private record StoredEvent(String publicId, String requestFingerprint) {
    }

    private record StoredCase(
            UUID id,
            String status,
            long workflowVersion,
            Instant riskAcceptedUntil,
            String decisionReason,
            String decisionEvidence
    ) {
    }
}
