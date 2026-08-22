package io.rbvm.postgres;

import io.rbvm.context.FindingBusinessServiceLink;
import io.rbvm.context.FindingBusinessServiceLinkRegistry;
import io.rbvm.context.FindingReachabilityScopeLink;
import io.rbvm.context.FindingReachabilityScopeLink.OriginScope;
import io.rbvm.context.FindingReachabilityScopeLink.TransportProtocol;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry;
import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingKind;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
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

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumMap;
import java.util.List;
import java.util.UUID;

/**
 * Live PostgreSQL integration coverage for V22 Decision Input V3.
 *
 * <p>This test proves that Finding-context associations are applied as-of the evaluation boundary
 * before evidence selection, that identically named context on another asset cannot contaminate the
 * Finding, and that persisted V3 snapshots remain exactly replayable after later UNLINKED events.</p>
 */
public final class PostgresV22LiveSelfTest {
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-4000-8000-000000000001");
    private static final UUID SOURCE_PROFILE_ID = UUID.fromString("20000000-0000-4000-8000-000000000001");
    private static final UUID FINDING_ASSET_ID = UUID.fromString("30000000-0000-4000-8000-000000000001");
    private static final UUID OTHER_ASSET_ID = UUID.fromString("30000000-0000-4000-8000-000000000002");
    private static final UUID FINDING_ID = UUID.fromString("70000000-0000-4000-8000-000000000001");

    private static final UUID REACHABILITY_A_ID = UUID.fromString("92000000-0000-4000-8000-000000000001");
    private static final UUID REACHABILITY_B_ID = UUID.fromString("92000000-0000-4000-8000-000000000002");
    private static final UUID IMPACT_A_ID = UUID.fromString("94000000-0000-4000-8000-000000000001");
    private static final UUID IMPACT_B_ID = UUID.fromString("94000000-0000-4000-8000-000000000002");

    private static final Instant T5 = Instant.parse("2026-08-21T00:05:00Z");
    private static final Instant T6 = Instant.parse("2026-08-21T00:06:00Z");
    private static final Instant T7 = Instant.parse("2026-08-21T00:07:00Z");
    private static final Instant T8 = Instant.parse("2026-08-21T00:08:00Z");
    private static final Instant T9 = Instant.parse("2026-08-21T00:09:00Z");
    private static final Instant T10 = Instant.parse("2026-08-21T00:10:00Z");

    private PostgresV22LiveSelfTest() {
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
        require(schemaVersion == 22, "expected schema version 22, found " + schemaVersion);

        invokeLegacy("seedCanonicalFinding", new Class<?>[]{JdbcConnectionFactory.class}, ownerConnections);
        seedScopedEvidence(ownerConnections);
        invokeLegacy("installRuntimeRole", new Class<?>[]{JdbcConnectionFactory.class}, ownerConnections);
        invokeLegacy("setRuntimePassword", new Class<?>[]{JdbcConnectionFactory.class}, ownerConnections);

        JdbcConnectionFactory runtimeConnections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                "rbvm_runtime",
                "rbvm-live-test"
        );

        exerciseV3(runtimeConnections, schemaVersion);
        proveAppendOnlyPrivileges(runtimeConnections);

        System.out.println(
                "PostgresV22LiveSelfTest: PASS schema=22 decision_v3=PASS "
                        + "as_of=PASS cross_asset=PASS replay=PASS append_only=PASS"
        );
    }

    private static void exerciseV3(JdbcConnectionFactory connections, int schemaVersion)
            throws Exception {
        RbvmDecisionMethodologyPolicy methodology = methodology(1);
        PostgresDecisionMethodologyPolicyStore policies = new PostgresDecisionMethodologyPolicyStore(
                connections,
                false,
                Clock.fixed(T7, ZoneOffset.UTC)
        );
        String policyStatus = policies.install(methodology).status().name();
        require(policyStatus.equals("INSERTED") || policyStatus.equals("REPLAYED"),
                "methodology install must be immutable/replayable");

        PostgresFindingReachabilityScopeLinkRegistry reachabilityLinks =
                new PostgresFindingReachabilityScopeLinkRegistry(
                        connections,
                        schemaVersion,
                        Clock.fixed(T7, ZoneOffset.UTC)
                );
        FindingReachabilityScopeLink.ChangeDraft reachLinked =
                FindingReachabilityScopeLink.ChangeDraft.linked(
                        OriginScope.INTERNET,
                        "Edge Probe",
                        TransportProtocol.TCP,
                        443,
                        "v22-live-operator",
                        "explicit Finding endpoint association"
                );
        var reachResult = reachabilityLinks.revise(FINDING_ID, 0, reachLinked);
        require(reachResult.status() == FindingReachabilityScopeLinkRegistry.MutationStatus.UPDATED,
                "reachability link revision 1 must append");
        UUID reachBindingId = reachResult.current().eventId();
        var reachReplay = reachabilityLinks.revise(FINDING_ID, 0, reachLinked);
        require(reachReplay.status() == FindingReachabilityScopeLinkRegistry.MutationStatus.REPLAYED,
                "exact reachability retry must replay");
        require(reachReplay.current().eventId().equals(reachBindingId),
                "reachability replay must retain original event ID");

        PostgresFindingBusinessServiceLinkRegistry businessLinks =
                new PostgresFindingBusinessServiceLinkRegistry(
                        connections,
                        schemaVersion,
                        Clock.fixed(T7, ZoneOffset.UTC)
                );
        FindingBusinessServiceLink.ChangeDraft businessLinked =
                FindingBusinessServiceLink.ChangeDraft.linked(
                        "Payments",
                        "v22-live-operator",
                        "explicit Finding service association"
                );
        var businessResult = businessLinks.revise(FINDING_ID, 0, businessLinked);
        require(businessResult.status() == FindingBusinessServiceLinkRegistry.MutationStatus.UPDATED,
                "business-service link revision 1 must append");
        UUID businessBindingId = businessResult.current().eventId();
        var businessReplay = businessLinks.revise(FINDING_ID, 0, businessLinked);
        require(businessReplay.status() == FindingBusinessServiceLinkRegistry.MutationStatus.REPLAYED,
                "exact business-service retry must replay");
        require(businessReplay.current().eventId().equals(businessBindingId),
                "business-service replay must retain original event ID");

        PostgresDecisionInputSnapshotBuilder builder = new PostgresDecisionInputSnapshotBuilder(
                connections,
                policies,
                schemaVersion
        );
        RbvmDecisionInputSnapshot beforeUnlink = builder.build(
                FINDING_ID,
                methodology.revision(),
                methodology.policySha256(),
                T8
        );
        require(beforeUnlink.isV3(), "schema 22 must build Decision Input Snapshot V3");
        require(!beforeUnlink.isV2(), "V3 must have a distinct contract identity from V2");

        var reachability = beforeUnlink.dimensions().get(EvidenceDimension.NETWORK_REACHABILITY);
        require(reachability.state() == DimensionState.PRESENT,
                "linked reachability evidence must be PRESENT");
        require(reachability.evidenceReferences().size() == 1,
                "cross-asset duplicate target must not add another reachability reference");
        EvidenceReference reachReference = reachability.evidenceReferences().get(0);
        require(reachReference.evidenceId().equals(REACHABILITY_A_ID),
                "only evidence on the Finding asset may qualify");
        require(reachReference.bindingReference() != null,
                "V3 reachability reference must retain exact association binding");
        require(reachReference.bindingReference().bindingKind()
                        == BindingKind.FINDING_REACHABILITY_SCOPE_LINK_EVENT,
                "reachability V3 binding kind must be exact");
        require(reachReference.bindingReference().bindingId().equals(reachBindingId),
                "reachability reference must bind exact revision-1 event");

        var business = beforeUnlink.dimensions().get(EvidenceDimension.BUSINESS_MISSION_IMPACT);
        require(business.state() == DimensionState.PRESENT,
                "linked business impact evidence must be PRESENT");
        require(business.evidenceReferences().size() == 1,
                "cross-asset duplicate service must not add another impact reference");
        EvidenceReference impactReference = business.evidenceReferences().get(0);
        require(impactReference.evidenceId().equals(IMPACT_A_ID),
                "only impact evidence on the Finding asset may qualify");
        require(impactReference.bindingReference() != null,
                "V3 business-impact reference must retain exact association binding");
        require(impactReference.bindingReference().bindingKind()
                        == BindingKind.FINDING_BUSINESS_SERVICE_LINK_EVENT,
                "business V3 binding kind must be exact");
        require(impactReference.bindingReference().bindingId().equals(businessBindingId),
                "business reference must bind exact revision-1 event");

        PostgresDecisionInputSnapshotStore snapshots = new PostgresDecisionInputSnapshotStore(
                connections,
                false,
                Clock.fixed(T8, ZoneOffset.UTC)
        );
        String installStatus = snapshots.install(beforeUnlink).status().name();
        require(installStatus.equals("INSERTED") || installStatus.equals("REPLAYED"),
                "V3 snapshot must persist immutably");
        RbvmDecisionInputSnapshot reread = snapshots
                .findBySha256(beforeUnlink.snapshotSha256())
                .orElseThrow();
        require(reread.equals(beforeUnlink), "persisted V3 snapshot must round-trip exactly");

        PostgresDecisionInputEvidenceResolver resolver = new PostgresDecisionInputEvidenceResolver(
                connections,
                schemaVersion
        );
        RbvmResolvedDecisionInput resolved = resolver.resolve(reread);
        require(resolved.evidence(EvidenceDimension.NETWORK_REACHABILITY).size() == 1,
                "resolver must return exactly one bound reachability row");
        require(resolved.evidence(EvidenceDimension.BUSINESS_MISSION_IMPACT).size() == 1,
                "resolver must return exactly one bound impact row");

        proveResolverRejectsCrossAssetReference(resolver, methodology, reachResult.current());

        PostgresFindingReachabilityScopeLinkRegistry laterReachabilityLinks =
                new PostgresFindingReachabilityScopeLinkRegistry(
                        connections,
                        schemaVersion,
                        Clock.fixed(T9, ZoneOffset.UTC)
                );
        var reachUnlink = laterReachabilityLinks.revise(
                FINDING_ID,
                1,
                FindingReachabilityScopeLink.ChangeDraft.unlinked(
                        OriginScope.INTERNET,
                        "edge probe",
                        TransportProtocol.TCP,
                        443,
                        "v22-live-operator",
                        "explicit later unlink"
                )
        );
        require(reachUnlink.status() == FindingReachabilityScopeLinkRegistry.MutationStatus.UPDATED,
                "reachability unlink must append revision 2");

        PostgresFindingBusinessServiceLinkRegistry laterBusinessLinks =
                new PostgresFindingBusinessServiceLinkRegistry(
                        connections,
                        schemaVersion,
                        Clock.fixed(T9, ZoneOffset.UTC)
                );
        var businessUnlink = laterBusinessLinks.revise(
                FINDING_ID,
                1,
                FindingBusinessServiceLink.ChangeDraft.unlinked(
                        "payments",
                        "v22-live-operator",
                        "explicit later unlink"
                )
        );
        require(businessUnlink.status() == FindingBusinessServiceLinkRegistry.MutationStatus.UPDATED,
                "business-service unlink must append revision 2");

        RbvmDecisionInputSnapshot historicalReplay = builder.build(
                FINDING_ID,
                methodology.revision(),
                methodology.policySha256(),
                T8
        );
        require(historicalReplay.equals(beforeUnlink),
                "later unlink must not change an as-of T8 V3 snapshot");
        require(snapshots.install(historicalReplay).status().name().equals("REPLAYED"),
                "same historical V3 evaluation must replay after later association changes");
        resolver.resolve(reread);

        RbvmDecisionInputSnapshot afterUnlink = builder.build(
                FINDING_ID,
                methodology.revision(),
                methodology.policySha256(),
                T10
        );
        require(afterUnlink.isV3(), "later build must remain V3");
        require(afterUnlink.dimensions().get(EvidenceDimension.NETWORK_REACHABILITY).state()
                        == DimensionState.MISSING,
                "effective UNLINKED reachability must yield no eligible evidence, not NOT_REACHABLE");
        require(afterUnlink.dimensions().get(EvidenceDimension.NETWORK_REACHABILITY)
                        .evidenceReferences().isEmpty(),
                "UNLINKED reachability must retain no native reference");
        require(afterUnlink.dimensions().get(EvidenceDimension.BUSINESS_MISSION_IMPACT).state()
                        == DimensionState.MISSING,
                "effective UNLINKED service must yield no eligible impact, not LOW");
        require(afterUnlink.dimensions().get(EvidenceDimension.BUSINESS_MISSION_IMPACT)
                        .evidenceReferences().isEmpty(),
                "UNLINKED business service must retain no native reference");
    }

    private static void proveResolverRejectsCrossAssetReference(
            PostgresDecisionInputEvidenceResolver resolver,
            RbvmDecisionMethodologyPolicy methodology,
            FindingReachabilityScopeLink bindingEvent
    ) throws Exception {
        BindingReference binding = new BindingReference(
                BindingKind.FINDING_REACHABILITY_SCOPE_LINK_EVENT,
                bindingEvent.eventId(),
                bindingEvent.evidenceSha256(),
                bindingEvent.linkMethod().name(),
                bindingEvent.recordedAt()
        );
        EvidenceReference wrongAsset = new EvidenceReference(
                EvidenceDimension.NETWORK_REACHABILITY,
                NativeEvidenceKind.NETWORK_REACHABILITY_EVIDENCE,
                REACHABILITY_B_ID,
                "b".repeat(64),
                "LIVE_REACHABILITY",
                T6,
                binding
        );
        EnumMap<EvidenceDimension, DimensionInput> dimensions = missingDimensions();
        dimensions.put(
                EvidenceDimension.NETWORK_REACHABILITY,
                new DimensionInput(
                        EvidenceDimension.NETWORK_REACHABILITY,
                        DimensionState.PRESENT,
                        List.of(wrongAsset)
                )
        );
        RbvmDecisionInputSnapshot malicious = RbvmDecisionInputSnapshot.createV3(
                FINDING_ID,
                methodology.revision(),
                methodology.policySha256(),
                T8,
                dimensions
        );
        boolean rejected = false;
        try {
            resolver.resolve(malicious);
        } catch (IOException expected) {
            rejected = expected.getMessage().contains("does not belong to snapshot Finding asset");
        }
        require(rejected,
                "resolver must reject same-target native evidence taken from another scanner asset");
    }

    private static void seedScopedEvidence(JdbcConnectionFactory connections) throws Exception {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            statement.execute("""
                    INSERT INTO rbvm.asset(
                        id, tenant_id, source_profile_id, observed_name, normalized_observed_name,
                        os_name_raw, identity_basis, identity_confidence,
                        first_observed_at, last_observed_at, created_at, updated_at, public_id
                    ) VALUES (
                        '30000000-0000-4000-8000-000000000002',
                        '10000000-0000-4000-8000-000000000001',
                        '20000000-0000-4000-8000-000000000001',
                        'other-web-01', 'other-web-01', 'Ubuntu 24.04',
                        'SOURCE_NAME_ONLY', 'LOW',
                        '2026-08-20T23:00:00Z', '2026-08-20T23:00:00Z',
                        '2026-08-20T23:00:00Z', '2026-08-20T23:00:00Z',
                        'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
                    ) ON CONFLICT DO NOTHING;

                    INSERT INTO rbvm.network_reachability_snapshot(
                        id, tenant_id, evidence_source, source_sha256, observed_at, ingested_at
                    ) VALUES
                    (
                        '91000000-0000-4000-8000-000000000001',
                        '10000000-0000-4000-8000-000000000001',
                        'LIVE_REACHABILITY',
                        '1111111111111111111111111111111111111111111111111111111111111111',
                        '2026-08-21T00:05:00Z', '2026-08-21T00:05:00Z'
                    ),
                    (
                        '91000000-0000-4000-8000-000000000002',
                        '10000000-0000-4000-8000-000000000001',
                        'LIVE_REACHABILITY',
                        '2222222222222222222222222222222222222222222222222222222222222222',
                        '2026-08-21T00:06:00Z', '2026-08-21T00:06:00Z'
                    );

                    INSERT INTO rbvm.network_reachability_evidence(
                        id, tenant_id, asset_id, snapshot_id,
                        asset_identity_basis, asset_name_observed, asset_source_id,
                        origin_scope, origin_label, transport_protocol, target_port, target_service,
                        reachability_status, reachability_method, ingested_at, evidence_sha256
                    ) VALUES
                    (
                        '92000000-0000-4000-8000-000000000001',
                        '10000000-0000-4000-8000-000000000001',
                        '30000000-0000-4000-8000-000000000001',
                        '91000000-0000-4000-8000-000000000001',
                        'SOURCE_NAME_ONLY', 'live-web-01', null,
                        'INTERNET', 'edge probe', 'TCP', 443, 'https',
                        'REACHABLE', 'CONTROL_PLANE',
                        '2026-08-21T00:05:00Z',
                        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                    ),
                    (
                        '92000000-0000-4000-8000-000000000002',
                        '10000000-0000-4000-8000-000000000001',
                        '30000000-0000-4000-8000-000000000002',
                        '91000000-0000-4000-8000-000000000002',
                        'SOURCE_NAME_ONLY', 'other-web-01', null,
                        'INTERNET', 'edge probe', 'TCP', 443, 'https',
                        'NOT_REACHABLE', 'CONTROL_PLANE',
                        '2026-08-21T00:06:00Z',
                        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                    );

                    INSERT INTO rbvm.business_impact_snapshot(
                        id, tenant_id, impact_source, source_sha256, observed_at, ingested_at
                    ) VALUES
                    (
                        '93000000-0000-4000-8000-000000000001',
                        '10000000-0000-4000-8000-000000000001',
                        'LIVE_IMPACT',
                        '3333333333333333333333333333333333333333333333333333333333333333',
                        '2026-08-21T00:05:00Z', '2026-08-21T00:05:00Z'
                    ),
                    (
                        '93000000-0000-4000-8000-000000000002',
                        '10000000-0000-4000-8000-000000000001',
                        'LIVE_IMPACT',
                        '4444444444444444444444444444444444444444444444444444444444444444',
                        '2026-08-21T00:06:00Z', '2026-08-21T00:06:00Z'
                    );

                    INSERT INTO rbvm.business_impact_evidence(
                        id, tenant_id, asset_id, snapshot_id,
                        asset_identity_basis, asset_name_observed, asset_source_id,
                        business_service, business_service_normalized,
                        impact_dimension, impact_level, impact_method, impact_statement,
                        ingested_at, evidence_sha256
                    ) VALUES
                    (
                        '94000000-0000-4000-8000-000000000001',
                        '10000000-0000-4000-8000-000000000001',
                        '30000000-0000-4000-8000-000000000001',
                        '93000000-0000-4000-8000-000000000001',
                        'SOURCE_NAME_ONLY', 'live-web-01', null,
                        'Payments', 'payments',
                        'OPERATIONAL', 'HIGH', 'SERVICE_OWNER_ATTESTATION',
                        'Payments outage causes major operational disruption.',
                        '2026-08-21T00:05:00Z',
                        'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
                    ),
                    (
                        '94000000-0000-4000-8000-000000000002',
                        '10000000-0000-4000-8000-000000000001',
                        '30000000-0000-4000-8000-000000000002',
                        '93000000-0000-4000-8000-000000000002',
                        'SOURCE_NAME_ONLY', 'other-web-01', null,
                        'Payments', 'payments',
                        'OPERATIONAL', 'SEVERE', 'SERVICE_OWNER_ATTESTATION',
                        'Other asset has separate severe impact evidence.',
                        '2026-08-21T00:06:00Z',
                        'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
                    );
                    """);
        }
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
                            List.of(),
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

    private static EnumMap<EvidenceDimension, DimensionInput> missingDimensions() {
        EnumMap<EvidenceDimension, DimensionInput> dimensions =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            dimensions.put(
                    dimension,
                    new DimensionInput(dimension, DimensionState.MISSING, List.of())
            );
        }
        return dimensions;
    }

    private static void proveAppendOnlyPrivileges(JdbcConnectionFactory connections)
            throws Exception {
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.executeUpdate(
                            "UPDATE rbvm.finding_reachability_scope_link_event "
                                    + "SET change_note = 'forbidden'")),
                    "runtime role must not UPDATE Finding reachability association history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.executeUpdate(
                            "DELETE FROM rbvm.finding_business_service_link_event")),
                    "runtime role must not DELETE Finding business-service association history");
        }
        try (Connection connection = connections.open(); Statement statement = connection.createStatement()) {
            require(rejected(() -> statement.executeUpdate(
                            "UPDATE rbvm.decision_input_snapshot SET snapshot_sha256 = snapshot_sha256")),
                    "runtime role must not UPDATE Decision Input snapshots");
        }
    }

    private static void invokeLegacy(String name, Class<?>[] parameterTypes, Object... args)
            throws Exception {
        Method method = PostgresV20LiveSelfTest.class.getDeclaredMethod(name, parameterTypes);
        method.setAccessible(true);
        try {
            method.invoke(null, args);
        } catch (InvocationTargetException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof Exception checked) {
                throw checked;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new IllegalStateException("Legacy PostgreSQL fixture setup failed", cause);
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
