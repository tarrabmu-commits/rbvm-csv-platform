package io.rbvm.postgres;

import io.rbvm.asset.ManagedAsset;
import io.rbvm.asset.ManagedAsset.ClassificationMethod;
import io.rbvm.asset.ManagedAsset.LifecycleStatus;
import io.rbvm.asset.ManagedAsset.RevisionDraft;
import io.rbvm.asset.ManagedAssetRegistry.MutationStatus;
import io.rbvm.asset.ScannerManagedAssetLink.ChangeDraft;
import io.rbvm.asset.ScannerManagedAssetLink.LinkStatus;
import io.rbvm.csv.AssetContextCsvEvidence.BusinessCriticality;
import io.rbvm.csv.AssetContextCsvEvidence.Environment;
import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingKind;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.NativeEvidenceKind;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.AmbiguityHandling;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.FreshnessMode;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.LegacyPriorityHandling;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.MissingEvidenceHandling;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.SourceSelectionMode;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.SubjectScope;
import io.rbvm.decision.RbvmResolvedDecisionInput;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumMap;
import java.util.Map;
import java.util.UUID;

/**
 * Live PostgreSQL integration coverage for the V18–V20 persistence path.
 *
 * <p>This test is intentionally excluded from the dependency-free PlatformSelfTest. The dedicated
 * PostgreSQL CI workflow supplies a pinned pgJDBC driver and a disposable PostgreSQL service.</p>
 */
public final class PostgresV20LiveSelfTest {
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-4000-8000-000000000001");
    private static final UUID SOURCE_PROFILE_ID = UUID.fromString("20000000-0000-4000-8000-000000000001");
    private static final UUID SCANNER_ASSET_ID = UUID.fromString("30000000-0000-4000-8000-000000000001");
    private static final UUID VULNERABILITY_ID = UUID.fromString("40000000-0000-4000-8000-000000000001");
    private static final UUID COMPONENT_ID = UUID.fromString("50000000-0000-4000-8000-000000000001");
    private static final UUID CASE_ID = UUID.fromString("60000000-0000-4000-8000-000000000001");
    private static final UUID FINDING_ID = UUID.fromString("70000000-0000-4000-8000-000000000001");
    private static final UUID MANAGED_ASSET_ID = UUID.fromString("80000000-0000-4000-8000-000000000001");

    private static final Instant T0 = Instant.parse("2026-08-21T00:00:00Z");
    private static final Instant T1 = Instant.parse("2026-08-21T00:01:00Z");
    private static final Instant T2 = Instant.parse("2026-08-21T00:02:00Z");
    private static final Instant T3 = Instant.parse("2026-08-21T00:03:00Z");
    private static final Instant T4 = Instant.parse("2026-08-21T00:04:00Z");
    private static final Instant T5 = Instant.parse("2026-08-21T00:05:00Z");
    private static final Instant T6 = Instant.parse("2026-08-21T00:06:00Z");

    private PostgresV20LiveSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(System.getenv());
        require(settings.enabled(), "PostgreSQL settings must be enabled");

        JdbcConnectionFactory ownerConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        int schemaVersion = new PostgresMigrator(ownerConnections).migrate();
        require(schemaVersion == 20, "expected schema version 20, found " + schemaVersion);

        seedCanonicalFinding(ownerConnections);
        installRuntimeRole(ownerConnections);
        setRuntimePassword(ownerConnections);

        JdbcConnectionFactory runtimeConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                "rbvm_runtime",
                "rbvm-live-test"
        );
        exerciseManagedAssetLinkAndDecisionInput(runtimeConnections, schemaVersion);
        proveAppendOnlyPrivileges(runtimeConnections);

        System.out.println("PostgresV20LiveSelfTest: PASS schema=20 managed_asset=PASS link=PASS decision_v2=PASS append_only=PASS");
    }

    private static void exerciseManagedAssetLinkAndDecisionInput(
            JdbcConnectionFactory connections,
            int schemaVersion
    ) throws Exception {
        PostgresManagedAssetRegistry assets = new PostgresManagedAssetRegistry(
                connections,
                schemaVersion,
                Clock.fixed(T0, ZoneOffset.UTC)
        );
        RevisionDraft initial = new RevisionDraft(
                LifecycleStatus.ACTIVE,
                "payments-api",
                Environment.UNKNOWN,
                "payments",
                "payments-owner",
                BusinessCriticality.UNKNOWN,
                ClassificationMethod.CUSTOMER_DIRECT,
                null,
                null,
                "live-test-operator",
                "initial customer-confirmed state"
        );
        var create = assets.create(MANAGED_ASSET_ID, "cmdb-payments-api", initial);
        require(create.status() == MutationStatus.CREATED, "managed asset create must insert revision 1");
        require(create.asset().currentRevision().revision() == 1, "managed asset revision 1 expected");
        require(create.asset().currentRevision().recordedAt().equals(T0), "managed asset clock must be exact");

        PostgresScannerManagedAssetLinkRegistry links = new PostgresScannerManagedAssetLinkRegistry(
                connections,
                schemaVersion,
                Clock.fixed(T1, ZoneOffset.UTC)
        );
        ChangeDraft linked = new ChangeDraft(
                LinkStatus.LINKED,
                MANAGED_ASSET_ID,
                "live-test-operator",
                "explicit customer-confirmed link"
        );
        var linkedResult = links.revise(SCANNER_ASSET_ID, 0, linked);
        require(linkedResult.status().name().equals("UPDATED"), "first link must append revision 1");
        require(linkedResult.current().revision() == 1, "link revision 1 expected");
        UUID linkEventId = linkedResult.current().eventId();

        var replay = links.revise(SCANNER_ASSET_ID, 0, linked);
        require(replay.status().name().equals("REPLAYED"), "exact first-link retry must replay");
        require(replay.current().eventId().equals(linkEventId), "replay must not append a second event");
        require(links.history(SCANNER_ASSET_ID, 10, null).orElseThrow().events().size() == 1,
                "link replay must keep one history event");
        require(links.list(10, null).assets().stream().anyMatch(asset ->
                        asset.scannerAssetId().equals(SCANNER_ASSET_ID)
                                && asset.current() != null
                                && asset.current().managedAssetId().equals(MANAGED_ASSET_ID)),
                "scanner list must expose the explicit current link");

        RbvmDecisionMethodologyPolicy methodology = methodology(1);
        PostgresDecisionMethodologyPolicyStore policies = new PostgresDecisionMethodologyPolicyStore(
                connections,
                false,
                Clock.fixed(T1, ZoneOffset.UTC)
        );
        String policyStatus = policies.install(methodology).status().name();
        require(policyStatus.equals("INSERTED") || policyStatus.equals("REPLAYED"),
                "methodology install must be immutable/replayable");

        PostgresDecisionInputSnapshotBuilder builder = new PostgresDecisionInputSnapshotBuilder(
                connections,
                policies,
                schemaVersion
        );
        RbvmDecisionInputSnapshot beforeManagedRevision = builder.build(
                FINDING_ID,
                methodology.revision(),
                methodology.policySha256(),
                T2
        );
        require(beforeManagedRevision.isV2(), "schema 20 must build Decision Input Snapshot V2");
        var assetContext = beforeManagedRevision.dimensions().get(EvidenceDimension.ASSET_CONTEXT);
        require(assetContext.state() == DimensionState.PRESENT,
                "linked managed asset context must be PRESENT when no V13 competitor exists");
        require(assetContext.evidenceReferences().size() == 1,
                "one managed asset context reference expected");
        var reference = assetContext.evidenceReferences().get(0);
        require(reference.nativeEvidenceKind() == NativeEvidenceKind.MANAGED_ASSET_REVISION,
                "managed asset reference must be typed");
        require(reference.evidenceId().equals(create.asset().currentRevision().id()),
                "snapshot must bind exact managed asset revision 1");
        require(reference.bindingReference() != null,
                "managed asset reference requires exact link binding");
        require(reference.bindingReference().bindingKind() == BindingKind.SCANNER_MANAGED_ASSET_LINK_EVENT,
                "binding kind must identify the link event");
        require(reference.bindingReference().bindingId().equals(linkEventId),
                "snapshot must bind exact link event revision 1");

        PostgresDecisionInputSnapshotStore snapshots = new PostgresDecisionInputSnapshotStore(
                connections,
                false,
                Clock.fixed(T2, ZoneOffset.UTC)
        );
        String installStatus = snapshots.install(beforeManagedRevision).status().name();
        require(installStatus.equals("INSERTED") || installStatus.equals("REPLAYED"),
                "snapshot V2 must persist immutably");
        RbvmDecisionInputSnapshot reread = snapshots
                .findBySha256(beforeManagedRevision.snapshotSha256())
                .orElseThrow();
        require(reread.equals(beforeManagedRevision), "persisted snapshot must round-trip exactly");

        PostgresDecisionInputEvidenceResolver resolver = new PostgresDecisionInputEvidenceResolver(
                connections,
                schemaVersion
        );
        RbvmResolvedDecisionInput resolved = resolver.resolve(reread);
        require(resolved.evidence(EvidenceDimension.ASSET_CONTEXT).size() == 1,
                "resolver must return exactly the retained managed asset reference");

        PostgresManagedAssetRegistry laterAssets = new PostgresManagedAssetRegistry(
                connections,
                schemaVersion,
                Clock.fixed(T3, ZoneOffset.UTC)
        );
        RevisionDraft revised = new RevisionDraft(
                LifecycleStatus.ACTIVE,
                "payments-api",
                Environment.PRODUCTION,
                "payments",
                "payments-owner",
                BusinessCriticality.HIGH,
                ClassificationMethod.CUSTOMER_DIRECT,
                null,
                null,
                "live-test-operator",
                "customer confirmed production/high"
        );
        var revisedResult = laterAssets.revise(MANAGED_ASSET_ID, 1, revised);
        require(revisedResult.status() == MutationStatus.UPDATED, "managed asset revision 2 must append");
        require(revisedResult.asset().currentRevision().revision() == 2, "managed asset revision 2 expected");

        RbvmDecisionInputSnapshot afterManagedRevision = builder.build(
                FINDING_ID,
                methodology.revision(),
                methodology.policySha256(),
                T4
        );
        var laterReference = afterManagedRevision.dimensions()
                .get(EvidenceDimension.ASSET_CONTEXT)
                .evidenceReferences()
                .get(0);
        require(laterReference.evidenceId().equals(revisedResult.asset().currentRevision().id()),
                "later as-of build must select managed asset revision 2");
        require(!laterReference.evidenceId().equals(reference.evidenceId()),
                "later revision must not rewrite the historical snapshot reference");
        require(snapshots.findBySha256(beforeManagedRevision.snapshotSha256()).orElseThrow()
                        .dimensions().get(EvidenceDimension.ASSET_CONTEXT)
                        .evidenceReferences().get(0).evidenceId().equals(reference.evidenceId()),
                "historical persisted snapshot must remain bound to revision 1");

        PostgresScannerManagedAssetLinkRegistry laterLinks = new PostgresScannerManagedAssetLinkRegistry(
                connections,
                schemaVersion,
                Clock.fixed(T5, ZoneOffset.UTC)
        );
        var unlink = laterLinks.revise(
                SCANNER_ASSET_ID,
                1,
                new ChangeDraft(
                        LinkStatus.UNLINKED,
                        null,
                        "live-test-operator",
                        "explicit unlink"
                )
        );
        require(unlink.status().name().equals("UPDATED"), "UNLINKED must append revision 2");
        require(unlink.current().revision() == 2, "unlink revision 2 expected");

        RbvmDecisionInputSnapshot afterUnlink = builder.build(
                FINDING_ID,
                methodology.revision(),
                methodology.policySha256(),
                T6
        );
        require(afterUnlink.dimensions().get(EvidenceDimension.ASSET_CONTEXT).state()
                        == DimensionState.MISSING,
                "latest explicit UNLINKED must suppress managed asset context without inventing UNKNOWN evidence");
        require(afterUnlink.dimensions().get(EvidenceDimension.ASSET_CONTEXT)
                        .evidenceReferences().isEmpty(),
                "UNLINKED as-of snapshot must retain no managed asset reference");
    }

    private static RbvmDecisionMethodologyPolicy methodology(int revision) {
        EnumMap<EvidenceDimension, EvidenceSelectionPolicy> evidencePolicies =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            evidencePolicies.put(
                    dimension,
                    new EvidenceSelectionPolicy(
                            dimension,
                            SourceSelectionMode.ALL_SOURCES,
                            java.util.List.of(),
                            FreshnessMode.NO_AGE_LIMIT,
                            null
                    )
            );
        }
        return RbvmDecisionMethodologyPolicy.create(
                revision,
                SubjectScope.FINDING,
                MissingEvidenceHandling.PRESERVE_UNKNOWN,
                AmbiguityHandling.PRESERVE_AMBIGUOUS,
                LegacyPriorityHandling.EXCLUDE_LEGACY_PRIORITY_TIER,
                evidencePolicies
        );
    }

    private static void seedCanonicalFinding(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            statement.execute("""
                    INSERT INTO rbvm.tenant(id, tenant_key, display_name, created_at)
                    VALUES ('10000000-0000-4000-8000-000000000001', 'local', 'Live Test', '2026-08-21T00:00:00Z')
                    ON CONFLICT (tenant_key) DO NOTHING;

                    INSERT INTO rbvm.source_profile(
                        id, tenant_id, external_key, source_type, contract_id, semantics, enabled, created_at
                    ) VALUES (
                        '20000000-0000-4000-8000-000000000001',
                        '10000000-0000-4000-8000-000000000001',
                        'live-pg-source', 'WAZUH_CSV', 'WAZUH_CSV_V1',
                        'POSITIVE_OBSERVATION_EXPORT', true, '2026-08-21T00:00:00Z'
                    ) ON CONFLICT DO NOTHING;

                    INSERT INTO rbvm.asset(
                        id, tenant_id, source_profile_id, observed_name, normalized_observed_name,
                        os_name_raw, identity_basis, identity_confidence,
                        first_observed_at, last_observed_at, created_at, updated_at, public_id
                    ) VALUES (
                        '30000000-0000-4000-8000-000000000001',
                        '10000000-0000-4000-8000-000000000001',
                        '20000000-0000-4000-8000-000000000001',
                        'live-web-01', 'live-web-01', 'Ubuntu 24.04',
                        'SOURCE_NAME_ONLY', 'LOW',
                        '2026-08-20T23:00:00Z', '2026-08-20T23:00:00Z',
                        '2026-08-20T23:00:00Z', '2026-08-20T23:00:00Z',
                        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    ) ON CONFLICT DO NOTHING;

                    INSERT INTO rbvm.vulnerability(id, cve_id, created_at)
                    VALUES (
                        '40000000-0000-4000-8000-000000000001',
                        'CVE-2099-9999', '2026-08-20T23:00:00Z'
                    ) ON CONFLICT DO NOTHING;

                    INSERT INTO rbvm.asset_component(
                        id, tenant_id, asset_id, observed_product_name, normalized_product_name,
                        version_status, first_observed_at, last_observed_at, created_at, updated_at, public_id
                    ) VALUES (
                        '50000000-0000-4000-8000-000000000001',
                        '10000000-0000-4000-8000-000000000001',
                        '30000000-0000-4000-8000-000000000001',
                        'openssl', 'openssl', 'UNKNOWN_FROM_SOURCE',
                        '2026-08-20T23:00:00Z', '2026-08-20T23:00:00Z',
                        '2026-08-20T23:00:00Z', '2026-08-20T23:00:00Z',
                        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                    ) ON CONFLICT DO NOTHING;

                    INSERT INTO rbvm.vulnerability_case(
                        id, tenant_id, source_profile_id, asset_id, vulnerability_id,
                        status, closure_policy, current_severity,
                        first_observed_at, last_observed_at, created_at, updated_at, public_id
                    ) VALUES (
                        '60000000-0000-4000-8000-000000000001',
                        '10000000-0000-4000-8000-000000000001',
                        '20000000-0000-4000-8000-000000000001',
                        '30000000-0000-4000-8000-000000000001',
                        '40000000-0000-4000-8000-000000000001',
                        'OPEN', 'POSITIVE_ONLY_NO_AUTO_CLOSE', 'HIGH',
                        '2026-08-20T23:00:00Z', '2026-08-20T23:00:00Z',
                        '2026-08-20T23:00:00Z', '2026-08-20T23:00:00Z',
                        'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
                    ) ON CONFLICT DO NOTHING;

                    INSERT INTO rbvm.exposure(
                        id, tenant_id, source_profile_id, case_id, asset_id, vulnerability_id, component_id,
                        status, closure_policy, current_severity, current_severity_observed_at,
                        first_observed_at, last_observed_at, observation_count,
                        severity_changed, timestamp_severity_conflict, created_at, updated_at,
                        public_id, lifecycle_observed_at, resolved_at
                    ) VALUES (
                        '70000000-0000-4000-8000-000000000001',
                        '10000000-0000-4000-8000-000000000001',
                        '20000000-0000-4000-8000-000000000001',
                        '60000000-0000-4000-8000-000000000001',
                        '30000000-0000-4000-8000-000000000001',
                        '40000000-0000-4000-8000-000000000001',
                        '50000000-0000-4000-8000-000000000001',
                        'ACTIVE', 'POSITIVE_ONLY_NO_AUTO_CLOSE', 'HIGH', '2026-08-20T23:00:00Z',
                        '2026-08-20T23:00:00Z', '2026-08-20T23:00:00Z', 1,
                        false, false, '2026-08-20T23:00:00Z', '2026-08-20T23:00:00Z',
                        'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
                        '2026-08-20T23:00:00Z', null
                    ) ON CONFLICT DO NOTHING;
                    """);
        }
    }

    private static void installRuntimeRole(JdbcConnectionFactory connections) throws Exception {
        String script = Files.readString(Path.of("db/security/runtime-role.sql"));
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            statement.execute(script);
        }
    }

    private static void setRuntimePassword(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            statement.execute("ALTER ROLE rbvm_runtime PASSWORD 'rbvm-live-test'");
        }
    }

    private static void proveAppendOnlyPrivileges(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            boolean managedUpdateRejected = rejected(() -> statement.executeUpdate(
                    "UPDATE rbvm.managed_asset_revision SET change_note = 'forbidden'"));
            require(managedUpdateRejected, "runtime role must not UPDATE managed asset revisions");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            boolean linkDeleteRejected = rejected(() -> statement.executeUpdate(
                    "DELETE FROM rbvm.scanner_managed_asset_link_event"));
            require(linkDeleteRejected, "runtime role must not DELETE link events");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            boolean snapshotUpdateRejected = rejected(() -> statement.executeUpdate(
                    "UPDATE rbvm.decision_input_snapshot SET snapshot_sha256 = snapshot_sha256"));
            require(snapshotUpdateRejected, "runtime role must not UPDATE decision input snapshots");
        }
    }

    private static boolean rejected(SqlAction action) throws Exception {
        try {
            action.run();
            return false;
        } catch (SQLException exception) {
            return "42501".equals(exception.getSQLState());
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @FunctionalInterface
    private interface SqlAction {
        void run() throws Exception;
    }
}
