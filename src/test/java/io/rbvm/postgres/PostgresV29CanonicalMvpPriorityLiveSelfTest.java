package io.rbvm.postgres;

import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Live proof of V29 exact-lineage canonical MVP-priority persistence and replay. */
public final class PostgresV29CanonicalMvpPriorityLiveSelfTest {
    private PostgresV29CanonicalMvpPriorityLiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(), settings.user(), settings.password());
        int schemaVersion = new PostgresMigrator(connections).migrate();
        require(schemaVersion >= 29, "canonical MVP priority live proof requires schema version 29+");

        Seed seed = seed(connections);
        CanonicalMvpPriorityStore store = new PostgresCanonicalMvpPriorityAccess(connections);
        UUID runId = UUID.randomUUID();
        UUID analysisId = UUID.randomUUID();
        String prioritySha = "c".repeat(64);
        Instant materializedAt = Instant.parse("2026-08-24T03:00:00Z");
        List<CanonicalMvpPriorityStore.PriorityRow> identical = List.of(
                ranked(2, 1, "Front 1 exact source row 2"),
                ranked(3, 1, "Front 1 exact source row 2")
        );

        CanonicalMvpPriorityStore.MaterializationResult inserted = store.materialize(
                seed.importId(), runId, analysisId, seed.sourceSha(), prioritySha,
                identical, materializedAt);
        require(inserted.canonicalFindings() == 1, "two exact source rows must collapse to one canonical Finding");
        require(inserted.mappedSourceRows() == 2, "both exact source rows must remain provenance");
        require(inserted.insertedResults() == 1 && inserted.replayedResults() == 0,
                "first materialization must insert exactly one result");

        CanonicalMvpPriorityStore.MaterializationResult replay = store.materialize(
                seed.importId(), runId, analysisId, seed.sourceSha(), prioritySha,
                identical, materializedAt.plusSeconds(30));
        require(replay.insertedResults() == 0 && replay.replayedResults() == 1,
                "exact retry must replay immutable content");

        CanonicalMvpPriorityStore.PriorityView view = store.latestForFinding(seed.findingPublicId())
                .orElseThrow(() -> new AssertionError("materialized Finding priority must be readable"));
        require(view.findingId().equals(seed.findingPublicId()), "read must preserve public Finding identity");
        require(view.front() != null && view.front() == 1, "read must expose exact Pareto front");
        require(view.sourceRowNumbers().equals(List.of(2L, 3L)), "read must expose both exact source rows");
        require(view.sourceCsvSha256().equals(seed.sourceSha()), "read must preserve source CSV SHA");
        require(view.priorityCsvSha256().equals(prioritySha), "read must preserve priority artifact SHA");
        require(view.internetFacing().equals("YES"), "customer Internet Facing must remain artifact-bound input");
        require(view.contextualCvssV4().compareTo(new BigDecimal("9.2")) == 0,
                "contextual CVSS v4 input must be preserved exactly");

        boolean sourceMismatchRejected = false;
        try {
            store.materialize(seed.importId(), UUID.randomUUID(), UUID.randomUUID(),
                    "d".repeat(64), prioritySha, identical, materializedAt);
        } catch (CanonicalMvpPriorityStore.ConflictException expected) {
            sourceMismatchRejected = expected.getMessage().contains("source SHA")
                    || expected.getMessage().contains("file SHA");
        }
        require(sourceMismatchRejected, "different CSV SHA must never associate to canonical import");

        boolean replayDriftRejected = false;
        try {
            store.materialize(seed.importId(), runId, analysisId, seed.sourceSha(), prioritySha,
                    List.of(ranked(2, 2, "Front 2 drift"), ranked(3, 2, "Front 2 drift")),
                    materializedAt.plusSeconds(60));
        } catch (CanonicalMvpPriorityStore.ConflictException expected) {
            replayDriftRejected = expected.getMessage().contains("different immutable content");
        }
        require(replayDriftRejected, "same immutable identity with changed priority must fail closed");

        boolean collapseAmbiguityRejected = false;
        try {
            store.materialize(seed.importId(), UUID.randomUUID(), UUID.randomUUID(), seed.sourceSha(),
                    "e".repeat(64),
                    List.of(ranked(2, 1, "row 2"), ranked(3, 2, "row 3 differs")),
                    materializedAt.plusSeconds(90));
        } catch (CanonicalMvpPriorityStore.ConflictException expected) {
            collapseAmbiguityRejected = expected.getMessage().contains("different MVP-priority outputs");
        }
        require(collapseAmbiguityRejected,
                "source rows collapsing to one Finding with different priority must be rejected");

        boolean updateBlocked = false;
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     UPDATE rbvm.finding_mvp_priority_result
                     SET explanation = 'mutated'
                     WHERE result_sha256 = ?
                     """)) {
            statement.setString(1, view.resultSha256());
            statement.executeUpdate();
        } catch (SQLException expected) {
            updateBlocked = expected.getMessage().contains("append-only");
        }
        require(updateBlocked, "V29 result rows must be append-only at database layer");

        require(store.latestForFinding("f".repeat(64)).isEmpty(),
                "unmaterialized Finding identity must not fabricate a priority");
        System.out.println("PostgresV29CanonicalMvpPriorityLiveSelfTest: PASS schema=" + schemaVersion);
    }

    private static CanonicalMvpPriorityStore.PriorityRow ranked(long sourceRow, int front, String explanation) {
        return new CanonicalMvpPriorityStore.PriorityRow(
                sourceRow,
                "RANKED_RELATIVE_ONLY",
                front,
                0L,
                1L,
                "",
                explanation,
                CanonicalMvpPriorityStore.METHOD_SHA256,
                true,
                "YES",
                "MISSION_CRITICAL",
                new BigDecimal("0.95805"),
                new BigDecimal("9.2")
        );
    }

    private static Seed seed(JdbcConnectionFactory connections) throws Exception {
        UUID sourceProfileId = UUID.randomUUID();
        UUID importId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        UUID vulnerabilityId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        UUID observationOne = UUID.randomUUID();
        UUID observationTwo = UUID.randomUUID();
        UUID caseId = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();
        String findingPublicId = "7".repeat(64);
        String sourceSha = "a".repeat(64);
        Instant time = Instant.parse("2026-08-24T02:00:00Z");

        try (Connection connection = connections.open()) {
            connection.setAutoCommit(false);
            try {
                UUID tenantId = localTenant(connection, time);
                execute(connection, """
                        INSERT INTO rbvm.source_profile
                            (id, tenant_id, external_key, source_type, contract_id, semantics, enabled, created_at)
                        VALUES (?, ?, ?, 'WAZUH_CSV', 'WAZUH_CSV_V1', 'POSITIVE_OBSERVATION_EXPORT', true, ?)
                        """, sourceProfileId, tenantId, "priority-v29-" + sourceProfileId, time);
                execute(connection, """
                        INSERT INTO rbvm.import_run
                            (id, tenant_id, source_profile_id, status, contract_id, semantics, commit_scope,
                             file_sha256, file_size_bytes, raw_evidence_uri,
                             logical_rows, accepted_rows, deduplicated_rows, quarantined_rows,
                             created_at, confirmed_at, materialized_at)
                        VALUES (?, ?, ?, 'COMPLETED', 'WAZUH_CSV_V1', 'POSITIVE_OBSERVATION_EXPORT',
                                'CANONICAL_DOMAIN_AND_RAW_EVIDENCE', ?, 200, ?, 2, 2, 0, 0, ?, ?, ?)
                        """, importId, tenantId, sourceProfileId, sourceSha,
                        "file:///canonical-priority-v29/" + importId + ".csv", time, time, time);
                execute(connection, """
                        INSERT INTO rbvm.asset
                            (id, tenant_id, source_profile_id, observed_name, normalized_observed_name,
                             os_name_raw, identity_basis, identity_confidence,
                             first_observed_at, last_observed_at, created_at, updated_at, public_id)
                        VALUES (?, ?, ?, 'priority-host', 'priority-host', 'Linux',
                                'SOURCE_NAME_ONLY', 'LOW', ?, ?, ?, ?, ?)
                        """, assetId, tenantId, sourceProfileId,
                        time, time.plusSeconds(60), time, time.plusSeconds(60), "8".repeat(64));
                execute(connection,
                        "INSERT INTO rbvm.vulnerability (id, cve_id, created_at) VALUES (?, ?, ?)",
                        vulnerabilityId, "CVE-2099-" + Math.abs(vulnerabilityId.hashCode() + 10000), time);
                execute(connection, """
                        INSERT INTO rbvm.asset_component
                            (id, tenant_id, asset_id, observed_product_name, normalized_product_name,
                             version_status, first_observed_at, last_observed_at, created_at, updated_at, public_id)
                        VALUES (?, ?, ?, 'priority-package', 'priority-package', 'UNKNOWN_FROM_SOURCE',
                                ?, ?, ?, ?, ?)
                        """, componentId, tenantId, assetId, time, time.plusSeconds(60),
                        time, time.plusSeconds(60), "9".repeat(64));
                insertObservation(connection, observationOne, tenantId, sourceProfileId, assetId,
                        vulnerabilityId, componentId, "4".repeat(64), time);
                insertObservation(connection, observationTwo, tenantId, sourceProfileId, assetId,
                        vulnerabilityId, componentId, "5".repeat(64), time.plusSeconds(60));
                execute(connection, """
                        INSERT INTO rbvm.import_observation
                            (tenant_id, import_id, observation_id, source_row_number, linked_at)
                        VALUES (?, ?, ?, 2, ?), (?, ?, ?, 3, ?)
                        """, tenantId, importId, observationOne, time,
                        tenantId, importId, observationTwo, time.plusSeconds(60));
                execute(connection, """
                        INSERT INTO rbvm.vulnerability_case
                            (id, tenant_id, source_profile_id, asset_id, vulnerability_id, status,
                             closure_policy, current_severity, first_observed_at, last_observed_at,
                             created_at, updated_at, public_id)
                        VALUES (?, ?, ?, ?, ?, 'OPEN', 'POSITIVE_ONLY_NO_AUTO_CLOSE', 'HIGH',
                                ?, ?, ?, ?, ?)
                        """, caseId, tenantId, sourceProfileId, assetId, vulnerabilityId,
                        time, time.plusSeconds(60), time, time.plusSeconds(60), "6".repeat(64));
                execute(connection, """
                        INSERT INTO rbvm.exposure
                            (id, tenant_id, source_profile_id, case_id, asset_id, vulnerability_id, component_id,
                             status, closure_policy, current_severity, current_severity_observed_at,
                             first_observed_at, last_observed_at, observation_count,
                             severity_changed, timestamp_severity_conflict, created_at, updated_at,
                             lifecycle_observed_at, resolved_at, public_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 'POSITIVE_ONLY_NO_AUTO_CLOSE', 'HIGH',
                                ?, ?, ?, 2, false, false, ?, ?, ?, NULL, ?)
                        """, findingId, tenantId, sourceProfileId, caseId, assetId, vulnerabilityId, componentId,
                        time.plusSeconds(60), time, time.plusSeconds(60), time, time.plusSeconds(60),
                        time.plusSeconds(60), findingPublicId);
                execute(connection, """
                        INSERT INTO rbvm.exposure_observation (tenant_id, exposure_id, observation_id)
                        VALUES (?, ?, ?), (?, ?, ?)
                        """, tenantId, findingId, observationOne, tenantId, findingId, observationTwo);
                connection.commit();
            } catch (Exception exception) {
                connection.rollback();
                throw exception;
            }
        }
        return new Seed(importId, findingId, findingPublicId, sourceSha);
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
                VALUES (?, ?, ?, ?, ?, ?, ?, 'HIGH', true, 'priority V29 observation', '', 'Linux', ?, ?)
                """, id, tenantId, sourceProfileId, assetId, vulnerabilityId, componentId,
                fingerprint, time, time);
    }

    private static UUID localTenant(Connection connection, Instant time) throws Exception {
        try (PreparedStatement select = connection.prepareStatement(
                "SELECT id FROM rbvm.tenant WHERE tenant_key = 'local'")) {
            try (ResultSet rows = select.executeQuery()) {
                if (rows.next()) return rows.getObject(1, UUID.class);
            }
        }
        UUID tenantId = UUID.randomUUID();
        execute(connection,
                "INSERT INTO rbvm.tenant (id, tenant_key, display_name, created_at) VALUES (?, 'local', ?, ?)",
                tenantId, "Local tenant", time);
        return tenantId;
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

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private record Seed(UUID importId, UUID findingId, String findingPublicId, String sourceSha) {
    }
}
