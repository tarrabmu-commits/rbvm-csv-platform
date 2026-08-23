package io.rbvm.postgres;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** Live proof that import-scoped Finding identity follows persisted observation lineage only. */
public final class PostgresCanonicalImportFindingManifestLiveSelfTest {
    private PostgresCanonicalImportFindingManifestLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        int schemaVersion = new PostgresMigrator(connections).migrate();
        require(schemaVersion >= 6, "Finding manifest live proof requires schema version 6+");

        Seed seed = seed(connections);
        PostgresCanonicalImportFindingExporter exporter =
                new PostgresCanonicalImportFindingExporter(connections);

        Optional<byte[]> exported = exporter.exportCsv(seed.importId());
        require(exported.isPresent(), "completed import must produce a manifest artifact");
        String csv = new String(exported.orElseThrow(), StandardCharsets.UTF_8);
        require(csv.startsWith("Import_ID,Finding_ID,Source_Row_Number,Source_Profile_Key,"),
                "manifest header must be stable");
        require(csv.contains(seed.importId().toString()), "manifest must bind exact import ID");
        require(csv.contains(seed.findingId().toString()), "manifest must expose exact exposure/Finding ID");
        require(csv.contains(",2," + seed.sourceProfileKey() + ","),
                "multiple linked observations must retain minimum source row provenance");
        require(occurrences(csv, seed.findingId().toString()) == 1,
                "one canonical Finding must be emitted once even with multiple import observations");
        require(!csv.contains(seed.unrelatedFindingId().toString()),
                "Finding from another import must never leak into import-scoped manifest");
        require(exporter.exportCsv(UUID.randomUUID()).isEmpty(),
                "unknown/non-completed import must not produce a manifest");

        System.out.println("PostgresCanonicalImportFindingManifestLiveSelfTest: PASS");
    }

    private static Seed seed(JdbcConnectionFactory connections) throws Exception {
        UUID tenantId = UUID.randomUUID();
        UUID sourceProfileId = UUID.randomUUID();
        UUID importId = UUID.randomUUID();
        UUID otherImportId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        UUID vulnerabilityId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        UUID observationOne = UUID.randomUUID();
        UUID observationTwo = UUID.randomUUID();
        UUID unrelatedObservation = UUID.randomUUID();
        UUID caseId = UUID.randomUUID();
        UUID unrelatedCaseId = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();
        UUID unrelatedFindingId = UUID.randomUUID();
        String profileKey = "manifest-live-" + sourceProfileId;
        Instant time = Instant.parse("2026-08-23T18:00:00Z");

        try (Connection connection = connections.open()) {
            connection.setAutoCommit(false);
            try {
                execute(connection,
                        "INSERT INTO rbvm.tenant (id, tenant_key, display_name, created_at) VALUES (?, ?, ?, ?)",
                        tenantId, "manifest-" + tenantId, "Manifest live tenant", time);
                execute(connection, """
                        INSERT INTO rbvm.source_profile
                            (id, tenant_id, external_key, source_type, contract_id, semantics, enabled, created_at)
                        VALUES (?, ?, ?, 'WAZUH_CSV', 'WAZUH_CSV_V1', 'POSITIVE_OBSERVATION_EXPORT', true, ?)
                        """, sourceProfileId, tenantId, profileKey, time);
                insertImport(connection, importId, tenantId, sourceProfileId, "a".repeat(64), time);
                insertImport(connection, otherImportId, tenantId, sourceProfileId, "b".repeat(64), time);
                execute(connection, """
                        INSERT INTO rbvm.asset
                            (id, tenant_id, source_profile_id, observed_name, normalized_observed_name,
                             os_name_raw, identity_basis, identity_confidence,
                             first_observed_at, last_observed_at, created_at, updated_at)
                        VALUES (?, ?, ?, 'manifest-host', 'manifest-host', 'Linux',
                                'SOURCE_NAME_ONLY', 'LOW', ?, ?, ?, ?)
                        """, assetId, tenantId, sourceProfileId, time, time, time, time);
                execute(connection,
                        "INSERT INTO rbvm.vulnerability (id, cve_id, created_at) VALUES (?, 'CVE-2099-999991', ?)",
                        vulnerabilityId, time);
                execute(connection, """
                        INSERT INTO rbvm.asset_component
                            (id, tenant_id, asset_id, observed_product_name, normalized_product_name,
                             version_status, first_observed_at, last_observed_at, created_at, updated_at)
                        VALUES (?, ?, ?, 'manifest-package', 'manifest-package', 'UNKNOWN_FROM_SOURCE', ?, ?, ?, ?)
                        """, componentId, tenantId, assetId, time, time, time, time);

                insertObservation(connection, observationOne, tenantId, sourceProfileId, assetId,
                        vulnerabilityId, componentId, "1".repeat(64), time);
                insertObservation(connection, observationTwo, tenantId, sourceProfileId, assetId,
                        vulnerabilityId, componentId, "2".repeat(64), time.plusSeconds(60));
                insertObservation(connection, unrelatedObservation, tenantId, sourceProfileId, assetId,
                        vulnerabilityId, componentId, "3".repeat(64), time.plusSeconds(120));
                execute(connection, """
                        INSERT INTO rbvm.import_observation
                            (tenant_id, import_id, observation_id, source_row_number, linked_at)
                        VALUES (?, ?, ?, 2, ?), (?, ?, ?, 3, ?), (?, ?, ?, 2, ?)
                        """,
                        tenantId, importId, observationOne, time,
                        tenantId, importId, observationTwo, time.plusSeconds(60),
                        tenantId, otherImportId, unrelatedObservation, time.plusSeconds(120));

                insertCase(connection, caseId, tenantId, sourceProfileId, assetId, vulnerabilityId, time);
                insertCase(connection, unrelatedCaseId, tenantId, sourceProfileId, assetId,
                        vulnerabilityId, time.plusSeconds(120));
                insertExposure(connection, findingId, tenantId, sourceProfileId, caseId, assetId,
                        vulnerabilityId, componentId, 2, time, time.plusSeconds(60));
                insertExposure(connection, unrelatedFindingId, tenantId, sourceProfileId, unrelatedCaseId,
                        assetId, vulnerabilityId, componentId, 1, time.plusSeconds(120), time.plusSeconds(120));
                execute(connection, """
                        INSERT INTO rbvm.exposure_observation (tenant_id, exposure_id, observation_id)
                        VALUES (?, ?, ?), (?, ?, ?), (?, ?, ?)
                        """,
                        tenantId, findingId, observationOne,
                        tenantId, findingId, observationTwo,
                        tenantId, unrelatedFindingId, unrelatedObservation);
                connection.commit();
            } catch (Exception exception) {
                connection.rollback();
                throw exception;
            }
        }
        return new Seed(importId, findingId, unrelatedFindingId, profileKey);
    }

    private static void insertImport(
            Connection connection,
            UUID importId,
            UUID tenantId,
            UUID sourceProfileId,
            String sha,
            Instant time
    ) throws Exception {
        execute(connection, """
                INSERT INTO rbvm.import_run
                    (id, tenant_id, source_profile_id, status, contract_id, semantics, commit_scope,
                     file_sha256, file_size_bytes, raw_evidence_uri,
                     logical_rows, accepted_rows, deduplicated_rows, quarantined_rows,
                     created_at, confirmed_at, materialized_at)
                VALUES (?, ?, ?, 'COMPLETED', 'WAZUH_CSV_V1', 'POSITIVE_OBSERVATION_EXPORT',
                        'CANONICAL_DOMAIN_AND_RAW_EVIDENCE', ?, 100, ?, 1, 1, 0, 0, ?, ?, ?)
                """, importId, tenantId, sourceProfileId, sha,
                "file:///manifest-live/" + importId + ".csv", time, time, time);
    }

    private static void insertObservation(
            Connection connection,
            UUID id,
            UUID tenantId,
            UUID sourceProfileId,
            UUID assetId,
            UUID vulnerabilityId,
            UUID componentId,
            String fingerprint,
            Instant time
    ) throws Exception {
        execute(connection, """
                INSERT INTO rbvm.observation
                    (id, tenant_id, source_profile_id, asset_id, vulnerability_id, component_id,
                     fingerprint, severity, source_severity_recognized, description_snapshot,
                     references_raw, os_name_raw, detected_at, first_ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'HIGH', true, 'manifest live observation', '', 'Linux', ?, ?)
                """, id, tenantId, sourceProfileId, assetId, vulnerabilityId, componentId,
                fingerprint, time, time);
    }

    private static void insertCase(
            Connection connection,
            UUID id,
            UUID tenantId,
            UUID sourceProfileId,
            UUID assetId,
            UUID vulnerabilityId,
            Instant time
    ) throws Exception {
        execute(connection, """
                INSERT INTO rbvm.vulnerability_case
                    (id, tenant_id, source_profile_id, asset_id, vulnerability_id, status,
                     closure_policy, current_severity, first_observed_at, last_observed_at,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'OPEN', 'POSITIVE_ONLY_NO_AUTO_CLOSE', 'HIGH', ?, ?, ?, ?)
                """, id, tenantId, sourceProfileId, assetId, vulnerabilityId, time, time, time, time);
    }

    private static void insertExposure(
            Connection connection,
            UUID id,
            UUID tenantId,
            UUID sourceProfileId,
            UUID caseId,
            UUID assetId,
            UUID vulnerabilityId,
            UUID componentId,
            long observationCount,
            Instant first,
            Instant last
    ) throws Exception {
        execute(connection, """
                INSERT INTO rbvm.exposure
                    (id, tenant_id, source_profile_id, case_id, asset_id, vulnerability_id, component_id,
                     status, closure_policy, current_severity, current_severity_observed_at,
                     first_observed_at, last_observed_at, observation_count,
                     severity_changed, timestamp_severity_conflict, created_at, updated_at,
                     lifecycle_observed_at, resolved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 'POSITIVE_ONLY_NO_AUTO_CLOSE', 'HIGH',
                        ?, ?, ?, ?, false, false, ?, ?, ?, NULL)
                """, id, tenantId, sourceProfileId, caseId, assetId, vulnerabilityId, componentId,
                last, first, last, observationCount, first, last, last);
    }

    private static void execute(Connection connection, String sql, Object... values) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int index = 0; index < values.length; index++) {
                Object value = values[index];
                if (value instanceof Instant instant) {
                    statement.setTimestamp(index + 1, Timestamp.from(instant));
                } else {
                    statement.setObject(index + 1, value);
                }
            }
            statement.executeUpdate();
        }
    }

    private static int occurrences(String text, String needle) {
        int count = 0;
        int offset = 0;
        while ((offset = text.indexOf(needle, offset)) >= 0) {
            count++;
            offset += needle.length();
        }
        return count;
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private record Seed(UUID importId, UUID findingId, UUID unrelatedFindingId, String sourceProfileKey) {
    }
}
