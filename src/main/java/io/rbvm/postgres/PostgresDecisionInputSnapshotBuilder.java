package io.rbvm.postgres;

import io.rbvm.decision.DecisionInputEvidenceSelection;
import io.rbvm.decision.DecisionInputEvidenceSelection.Candidate;
import io.rbvm.decision.DecisionInputEvidenceSelection.Selection;
import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingKind;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.NativeEvidenceKind;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.Normalizer;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * PostgreSQL builder for one Finding-scoped Decision Input Snapshot.
 *
 * <p>The builder reads native immutable evidence history under one REPEATABLE READ transaction,
 * applies one explicitly requested methodology revision/SHA, and returns typed evidence references.
 * Schema V22 builds Decision Input V3: Finding-specific association history is resolved as-of the
 * evaluation boundary before Reachability or Business/Mission Impact candidates enter methodology
 * source/freshness selection. It does not calculate any RBVM score, priority, SLA, treatment,
 * source ranking, or Case roll-up.</p>
 */
public final class PostgresDecisionInputSnapshotBuilder implements DecisionInputSnapshotBuilder {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 17;
    private static final int V2_SCHEMA_VERSION = 20;
    private static final int V3_SCHEMA_VERSION = 22;

    private final JdbcConnectionFactory connections;
    private final DecisionMethodologyPolicyStore methodologyPolicies;
    private final int schemaVersion;

    public PostgresDecisionInputSnapshotBuilder(
            JdbcConnectionFactory connections,
            boolean migrate
    ) throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        PostgresDecisionMethodologyPolicyStore policyStore =
                new PostgresDecisionMethodologyPolicyStore(connections, migrate);
        this.methodologyPolicies = policyStore;
        this.schemaVersion = policyStore.schemaVersion();
        requireSchemaVersion(schemaVersion);
    }

    PostgresDecisionInputSnapshotBuilder(
            JdbcConnectionFactory connections,
            DecisionMethodologyPolicyStore methodologyPolicies,
            int schemaVersion
    ) throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        this.methodologyPolicies = Objects.requireNonNull(methodologyPolicies, "methodologyPolicies");
        this.schemaVersion = schemaVersion;
        requireSchemaVersion(schemaVersion);
    }

    @Override
    public RbvmDecisionInputSnapshot build(
            UUID findingId,
            int methodologyRevision,
            String methodologyPolicySha256,
            Instant evaluatedAt
    ) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        if (methodologyRevision < 1) {
            throw new IllegalArgumentException("methodologyRevision must be positive");
        }
        requireSha(methodologyPolicySha256, "methodologyPolicySha256");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");

        RbvmDecisionMethodologyPolicy methodology = methodologyPolicies
                .findByRevision(methodologyRevision)
                .orElseThrow(() -> new IOException(
                        "Decision input builder methodology revision is not registered"));
        if (!methodology.policySha256().equals(methodologyPolicySha256)) {
            throw new IOException(
                    "Decision input builder methodology revision/SHA does not match the registered policy");
        }

        try (Connection connection = connections.open()) {
            beginReadTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                FindingScope finding = requireFinding(connection, tenantId, findingId);
                EnumMap<EvidenceDimension, DimensionInput> dimensions =
                        new EnumMap<>(EvidenceDimension.class);

                for (EvidenceDimension dimension : EvidenceDimension.values()) {
                    EvidenceSelectionPolicy selectionPolicy = Objects.requireNonNull(
                            methodology.evidencePolicies().get(dimension),
                            "methodology evidence policy"
                    );
                    List<Candidate> candidates = loadCandidates(
                            connection,
                            tenantId,
                            finding,
                            dimension,
                            evaluatedAt,
                            schemaVersion
                    );
                    Selection selection = DecisionInputEvidenceSelection.select(
                            selectionPolicy,
                            evaluatedAt,
                            candidates
                    );
                    dimensions.put(
                            dimension,
                            new DimensionInput(
                                    dimension,
                                    selection.state(),
                                    selection.evidenceReferences()
                            )
                    );
                }

                RbvmDecisionInputSnapshot snapshot;
                if (schemaVersion >= V3_SCHEMA_VERSION) {
                    snapshot = RbvmDecisionInputSnapshot.createV3(
                            findingId,
                            methodology.revision(),
                            methodology.policySha256(),
                            evaluatedAt,
                            dimensions
                    );
                } else if (schemaVersion >= V2_SCHEMA_VERSION) {
                    snapshot = RbvmDecisionInputSnapshot.createV2(
                            findingId,
                            methodology.revision(),
                            methodology.policySha256(),
                            evaluatedAt,
                            dimensions
                    );
                } else {
                    snapshot = RbvmDecisionInputSnapshot.create(
                            findingId,
                            methodology.revision(),
                            methodology.policySha256(),
                            evaluatedAt,
                            dimensions
                    );
                }
                connection.commit();
                return snapshot;
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) {
                    throw ioException;
                }
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL decision input snapshot build failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL decision input snapshot build transaction",
                    exception
            );
        }
    }

    public int schemaVersion() {
        return schemaVersion;
    }

    private static void requireSchemaVersion(int schemaVersion) throws IOException {
        if (schemaVersion < REQUIRED_SCHEMA_VERSION) {
            throw new IOException(
                    "PostgreSQL schema version " + schemaVersion
                            + " is older than required version " + REQUIRED_SCHEMA_VERSION);
        }
    }

    private static void beginReadTransaction(Connection connection) throws SQLException {
        connection.setReadOnly(true);
        connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
        connection.setAutoCommit(false);
    }

    private static UUID requireTenant(Connection connection) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT id FROM rbvm.tenant WHERE tenant_key = ?")) {
            statement.setString(1, TENANT_KEY);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new IOException(
                            "PostgreSQL projection tenant has not been initialized before decision input build");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static FindingScope requireFinding(
            Connection connection,
            UUID tenantId,
            UUID findingId
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT asset_id, vulnerability_id
                FROM rbvm.exposure
                WHERE tenant_id = ? AND id = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, findingId);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new IOException(
                            "Decision input builder Finding_ID does not resolve to an existing canonical finding");
                }
                return new FindingScope(
                        findingId,
                        rows.getObject(1, UUID.class),
                        rows.getObject(2, UUID.class)
                );
            }
        }
    }

    private static List<Candidate> loadCandidates(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            EvidenceDimension dimension,
            Instant evaluatedAt,
            int schemaVersion
    ) throws SQLException, IOException {
        return switch (dimension) {
            case APPLICABILITY -> loadApplicability(
                    connection, tenantId, finding, evaluatedAt);
            case TECHNICAL_SEVERITY -> loadCvss(
                    connection, tenantId, finding, evaluatedAt);
            case KNOWN_EXPLOITATION -> loadKev(
                    connection, tenantId, finding, evaluatedAt);
            case EXPLOITATION_PROBABILITY -> loadEpss(
                    connection, tenantId, finding, evaluatedAt);
            case ASSET_CONTEXT -> loadAssetContext(
                    connection, tenantId, finding, evaluatedAt, schemaVersion);
            case NETWORK_REACHABILITY -> loadNetworkReachability(
                    connection, tenantId, finding, evaluatedAt, schemaVersion);
            case BUSINESS_MISSION_IMPACT -> loadBusinessImpact(
                    connection, tenantId, finding, evaluatedAt, schemaVersion);
        };
    }

    private static List<Candidate> loadApplicability(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            Instant evaluatedAt
    ) throws SQLException, IOException {
        List<Candidate> output = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, evidence_sha256, evidence_source, evaluated_at
                FROM rbvm.applicability_assessment
                WHERE tenant_id = ?
                  AND finding_id = ?
                  AND evaluated_at <= ?
                ORDER BY evaluated_at, id
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, finding.findingId());
            statement.setTimestamp(3, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    output.add(candidate(
                            EvidenceDimension.APPLICABILITY,
                            subgrain("finding", finding.findingId().toString()),
                            rows.getObject(1, UUID.class),
                            rows.getString(2),
                            rows.getString(3),
                            rows.getTimestamp(4).toInstant()
                    ));
                }
            }
        }
        return List.copyOf(output);
    }

    private static List<Candidate> loadCvss(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            Instant evaluatedAt
    ) throws SQLException, IOException {
        List<Candidate> output = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, evidence_sha256, cvss_source, observed_at
                FROM rbvm.cvss_v31_base_evidence
                WHERE tenant_id = ?
                  AND vulnerability_id = ?
                  AND observed_at <= ?
                ORDER BY observed_at, id
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, finding.vulnerabilityId());
            statement.setTimestamp(3, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    output.add(candidate(
                            EvidenceDimension.TECHNICAL_SEVERITY,
                            vulnerabilitySubgrain(finding),
                            rows.getObject(1, UUID.class),
                            rows.getString(2),
                            rows.getString(3),
                            rows.getTimestamp(4).toInstant()
                    ));
                }
            }
        }
        return List.copyOf(output);
    }

    private static List<Candidate> loadKev(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            Instant evaluatedAt
    ) throws SQLException, IOException {
        List<Candidate> output = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.id, e.evidence_sha256, s.kev_source, s.observed_at
                FROM rbvm.cisa_kev_evidence e
                JOIN rbvm.cisa_kev_catalog_snapshot s
                  ON s.tenant_id = e.tenant_id
                 AND s.id = e.snapshot_id
                WHERE e.tenant_id = ?
                  AND e.vulnerability_id = ?
                  AND s.observed_at <= ?
                ORDER BY s.observed_at, e.id
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, finding.vulnerabilityId());
            statement.setTimestamp(3, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    output.add(candidate(
                            EvidenceDimension.KNOWN_EXPLOITATION,
                            vulnerabilitySubgrain(finding),
                            rows.getObject(1, UUID.class),
                            rows.getString(2),
                            rows.getString(3),
                            rows.getTimestamp(4).toInstant()
                    ));
                }
            }
        }
        return List.copyOf(output);
    }

    /**
     * EPSS native chronology is publication-date first. An offline replay of an older score file may
     * have a later observed_at, so only the latest score_date frontier per semantic source is passed
     * to the generic selector. The selector then applies latest observed_at, allowlist, ambiguity,
     * and freshness semantics without inspecting probability or percentile values.
     */
    private static List<Candidate> loadEpss(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            Instant evaluatedAt
    ) throws SQLException, IOException {
        List<EpssCandidate> rowsFound = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.id, e.evidence_sha256, s.epss_source, s.score_date, s.observed_at
                FROM rbvm.epss_evidence e
                JOIN rbvm.epss_score_snapshot s
                  ON s.tenant_id = e.tenant_id
                 AND s.id = e.snapshot_id
                WHERE e.tenant_id = ?
                  AND e.vulnerability_id = ?
                  AND s.observed_at <= ?
                ORDER BY s.epss_source, s.score_date, s.observed_at, e.id
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, finding.vulnerabilityId());
            statement.setTimestamp(3, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Candidate candidate = candidate(
                            EvidenceDimension.EXPLOITATION_PROBABILITY,
                            vulnerabilitySubgrain(finding),
                            rows.getObject(1, UUID.class),
                            rows.getString(2),
                            rows.getString(3),
                            rows.getTimestamp(5).toInstant()
                    );
                    rowsFound.add(new EpssCandidate(candidate, rows.getObject(4, LocalDate.class)));
                }
            }
        }

        Map<String, LocalDate> latestScoreDateBySource = new HashMap<>();
        for (EpssCandidate item : rowsFound) {
            latestScoreDateBySource.merge(
                    item.candidate().evidenceSource(),
                    item.scoreDate(),
                    (left, right) -> left.compareTo(right) >= 0 ? left : right
            );
        }

        List<Candidate> output = new ArrayList<>();
        for (EpssCandidate item : rowsFound) {
            if (item.scoreDate().equals(
                    latestScoreDateBySource.get(item.candidate().evidenceSource()))) {
                output.add(item.candidate());
            }
        }
        return List.copyOf(output);
    }

    private static List<Candidate> loadAssetContext(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            Instant evaluatedAt,
            int schemaVersion
    ) throws SQLException, IOException {
        List<Candidate> output = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.id, e.evidence_sha256, s.context_source, s.observed_at
                FROM rbvm.asset_context_evidence e
                JOIN rbvm.asset_context_snapshot s
                  ON s.tenant_id = e.tenant_id
                 AND s.id = e.snapshot_id
                WHERE e.tenant_id = ?
                  AND e.asset_id = ?
                  AND s.observed_at <= ?
                ORDER BY s.observed_at, e.id
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, finding.assetId());
            statement.setTimestamp(3, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    output.add(candidate(
                            EvidenceDimension.ASSET_CONTEXT,
                            assetSubgrain(finding),
                            rows.getObject(1, UUID.class),
                            rows.getString(2),
                            rows.getString(3),
                            rows.getTimestamp(4).toInstant()
                    ));
                }
            }
        }
        if (schemaVersion >= V2_SCHEMA_VERSION) {
            loadManagedAssetContext(connection, tenantId, finding, evaluatedAt, output);
        }
        return List.copyOf(output);
    }

    private static void loadManagedAssetContext(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            Instant evaluatedAt,
            List<Candidate> output
    ) throws SQLException, IOException {
        UUID linkEventId;
        String linkSha256;
        String linkMethod;
        Instant linkRecordedAt;
        String linkStatus;
        UUID managedAssetId;
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, evidence_sha256, link_method, recorded_at,
                       link_status, managed_asset_id
                FROM rbvm.scanner_managed_asset_link_event
                WHERE tenant_id = ?
                  AND scanner_asset_id = ?
                  AND recorded_at <= ?
                ORDER BY revision DESC
                LIMIT 1
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, finding.assetId());
            statement.setTimestamp(3, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return;
                }
                linkEventId = rows.getObject(1, UUID.class);
                linkSha256 = rows.getString(2);
                linkMethod = rows.getString(3);
                linkRecordedAt = rows.getTimestamp(4).toInstant();
                linkStatus = rows.getString(5);
                managedAssetId = rows.getObject(6, UUID.class);
            }
        }
        if ("UNLINKED".equals(linkStatus)) {
            return;
        }
        if (!"LINKED".equals(linkStatus) || managedAssetId == null) {
            throw new IOException("Persisted scanner-managed-asset link state is invalid");
        }

        BindingReference binding = binding(
                BindingKind.SCANNER_MANAGED_ASSET_LINK_EVENT,
                linkEventId,
                linkSha256,
                linkMethod,
                linkRecordedAt,
                "Persisted scanner-managed-asset link provenance is invalid"
        );

        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, evidence_sha256, context_source, recorded_at
                FROM rbvm.managed_asset_revision
                WHERE tenant_id = ?
                  AND managed_asset_id = ?
                  AND recorded_at <= ?
                ORDER BY revision DESC
                LIMIT 1
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, managedAssetId);
            statement.setTimestamp(3, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return;
                }
                try {
                    output.add(new Candidate(
                            EvidenceDimension.ASSET_CONTEXT,
                            assetSubgrain(finding),
                            NativeEvidenceKind.MANAGED_ASSET_REVISION,
                            rows.getObject(1, UUID.class),
                            rows.getString(2).trim(),
                            rows.getString(3),
                            rows.getTimestamp(4).toInstant(),
                            binding
                    ));
                } catch (IllegalArgumentException | NullPointerException exception) {
                    throw new IOException(
                            "Persisted managed asset context metadata is invalid",
                            exception
                    );
                }
            }
        }
    }

    private static List<Candidate> loadNetworkReachability(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            Instant evaluatedAt,
            int schemaVersion
    ) throws SQLException, IOException {
        if (schemaVersion >= V3_SCHEMA_VERSION) {
            return loadNetworkReachabilityV3(connection, tenantId, finding, evaluatedAt);
        }
        return loadNetworkReachabilityLegacy(connection, tenantId, finding, evaluatedAt);
    }

    private static List<Candidate> loadNetworkReachabilityLegacy(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            Instant evaluatedAt
    ) throws SQLException, IOException {
        List<Candidate> output = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.id, e.evidence_sha256, s.evidence_source, s.observed_at,
                       e.origin_scope, e.origin_label, e.transport_protocol, e.target_port
                FROM rbvm.network_reachability_evidence e
                JOIN rbvm.network_reachability_snapshot s
                  ON s.tenant_id = e.tenant_id
                 AND s.id = e.snapshot_id
                WHERE e.tenant_id = ?
                  AND e.asset_id = ?
                  AND s.observed_at <= ?
                ORDER BY s.observed_at, e.id
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, finding.assetId());
            statement.setTimestamp(3, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Object portValue = rows.getObject(8);
                    String port = portValue == null ? "" : Integer.toString(((Number) portValue).intValue());
                    output.add(candidate(
                            EvidenceDimension.NETWORK_REACHABILITY,
                            subgrain(
                                    "reachability",
                                    finding.assetId().toString(),
                                    rows.getString(5),
                                    normalizeKey(rows.getString(6)),
                                    rows.getString(7),
                                    port
                            ),
                            rows.getObject(1, UUID.class),
                            rows.getString(2),
                            rows.getString(3),
                            rows.getTimestamp(4).toInstant()
                    ));
                }
            }
        }
        return List.copyOf(output);
    }

    private static List<Candidate> loadNetworkReachabilityV3(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            Instant evaluatedAt
    ) throws SQLException, IOException {
        List<Candidate> output = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                WITH latest_link AS (
                    SELECT DISTINCT ON (
                        origin_scope, origin_label_normalized,
                        transport_protocol, target_port_key
                    )
                        tenant_id, id, evidence_sha256, link_method, recorded_at,
                        link_status, origin_scope, origin_label_normalized,
                        transport_protocol, target_port_key
                    FROM rbvm.finding_reachability_scope_link_event
                    WHERE tenant_id = ?
                      AND finding_id = ?
                      AND recorded_at <= ?
                    ORDER BY
                        origin_scope, origin_label_normalized,
                        transport_protocol, target_port_key,
                        revision DESC
                )
                SELECT e.id, e.evidence_sha256, s.evidence_source, s.observed_at,
                       e.origin_scope, e.origin_label, e.transport_protocol, e.target_port,
                       l.id, l.evidence_sha256, l.link_method, l.recorded_at
                FROM latest_link l
                JOIN rbvm.network_reachability_evidence e
                  ON e.tenant_id = l.tenant_id
                 AND e.asset_id = ?
                 AND e.origin_scope = l.origin_scope
                 AND e.origin_label = l.origin_label_normalized
                 AND e.transport_protocol = l.transport_protocol
                 AND COALESCE(e.target_port, 0) = l.target_port_key
                JOIN rbvm.network_reachability_snapshot s
                  ON s.tenant_id = e.tenant_id
                 AND s.id = e.snapshot_id
                WHERE l.link_status = 'LINKED'
                  AND s.observed_at <= ?
                ORDER BY
                    e.origin_scope, e.origin_label, e.transport_protocol,
                    COALESCE(e.target_port, 0), s.observed_at, e.id
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, finding.findingId());
            statement.setTimestamp(3, Timestamp.from(evaluatedAt));
            statement.setObject(4, finding.assetId());
            statement.setTimestamp(5, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    Object portValue = rows.getObject(8);
                    String port = portValue == null ? "" : Integer.toString(((Number) portValue).intValue());
                    BindingReference association = binding(
                            BindingKind.FINDING_REACHABILITY_SCOPE_LINK_EVENT,
                            rows.getObject(9, UUID.class),
                            rows.getString(10),
                            rows.getString(11),
                            rows.getTimestamp(12).toInstant(),
                            "Persisted Finding reachability association provenance is invalid"
                    );
                    output.add(boundCandidate(
                            EvidenceDimension.NETWORK_REACHABILITY,
                            subgrain(
                                    "reachability",
                                    finding.assetId().toString(),
                                    rows.getString(5),
                                    normalizeKey(rows.getString(6)),
                                    rows.getString(7),
                                    port
                            ),
                            NativeEvidenceKind.NETWORK_REACHABILITY_EVIDENCE,
                            rows.getObject(1, UUID.class),
                            rows.getString(2),
                            rows.getString(3),
                            rows.getTimestamp(4).toInstant(),
                            association
                    ));
                }
            }
        }
        return List.copyOf(output);
    }

    private static List<Candidate> loadBusinessImpact(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            Instant evaluatedAt,
            int schemaVersion
    ) throws SQLException, IOException {
        if (schemaVersion >= V3_SCHEMA_VERSION) {
            return loadBusinessImpactV3(connection, tenantId, finding, evaluatedAt);
        }
        return loadBusinessImpactLegacy(connection, tenantId, finding, evaluatedAt);
    }

    private static List<Candidate> loadBusinessImpactLegacy(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            Instant evaluatedAt
    ) throws SQLException, IOException {
        List<Candidate> output = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.id, e.evidence_sha256, s.impact_source, s.observed_at,
                       e.business_service_normalized, e.impact_dimension
                FROM rbvm.business_impact_evidence e
                JOIN rbvm.business_impact_snapshot s
                  ON s.tenant_id = e.tenant_id
                 AND s.id = e.snapshot_id
                WHERE e.tenant_id = ?
                  AND e.asset_id = ?
                  AND s.observed_at <= ?
                ORDER BY s.observed_at, e.id
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, finding.assetId());
            statement.setTimestamp(3, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    output.add(candidate(
                            EvidenceDimension.BUSINESS_MISSION_IMPACT,
                            subgrain(
                                    "business-impact",
                                    finding.assetId().toString(),
                                    rows.getString(5).trim(),
                                    rows.getString(6)
                            ),
                            rows.getObject(1, UUID.class),
                            rows.getString(2),
                            rows.getString(3),
                            rows.getTimestamp(4).toInstant()
                    ));
                }
            }
        }
        return List.copyOf(output);
    }

    private static List<Candidate> loadBusinessImpactV3(
            Connection connection,
            UUID tenantId,
            FindingScope finding,
            Instant evaluatedAt
    ) throws SQLException, IOException {
        List<Candidate> output = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                WITH latest_link AS (
                    SELECT DISTINCT ON (business_service_normalized)
                        tenant_id, id, evidence_sha256, link_method, recorded_at,
                        link_status, business_service_normalized
                    FROM rbvm.finding_business_service_link_event
                    WHERE tenant_id = ?
                      AND finding_id = ?
                      AND recorded_at <= ?
                    ORDER BY business_service_normalized, revision DESC
                )
                SELECT e.id, e.evidence_sha256, s.impact_source, s.observed_at,
                       e.business_service_normalized, e.impact_dimension,
                       l.id, l.evidence_sha256, l.link_method, l.recorded_at
                FROM latest_link l
                JOIN rbvm.business_impact_evidence e
                  ON e.tenant_id = l.tenant_id
                 AND e.asset_id = ?
                 AND e.business_service_normalized = l.business_service_normalized
                JOIN rbvm.business_impact_snapshot s
                  ON s.tenant_id = e.tenant_id
                 AND s.id = e.snapshot_id
                WHERE l.link_status = 'LINKED'
                  AND s.observed_at <= ?
                ORDER BY
                    e.business_service_normalized, e.impact_dimension,
                    s.observed_at, e.id
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, finding.findingId());
            statement.setTimestamp(3, Timestamp.from(evaluatedAt));
            statement.setObject(4, finding.assetId());
            statement.setTimestamp(5, Timestamp.from(evaluatedAt));
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    BindingReference association = binding(
                            BindingKind.FINDING_BUSINESS_SERVICE_LINK_EVENT,
                            rows.getObject(7, UUID.class),
                            rows.getString(8),
                            rows.getString(9),
                            rows.getTimestamp(10).toInstant(),
                            "Persisted Finding business-service association provenance is invalid"
                    );
                    output.add(boundCandidate(
                            EvidenceDimension.BUSINESS_MISSION_IMPACT,
                            subgrain(
                                    "business-impact",
                                    finding.assetId().toString(),
                                    rows.getString(5).trim(),
                                    rows.getString(6)
                            ),
                            NativeEvidenceKind.BUSINESS_IMPACT_EVIDENCE,
                            rows.getObject(1, UUID.class),
                            rows.getString(2),
                            rows.getString(3),
                            rows.getTimestamp(4).toInstant(),
                            association
                    ));
                }
            }
        }
        return List.copyOf(output);
    }

    private static Candidate candidate(
            EvidenceDimension dimension,
            String subgrain,
            UUID evidenceId,
            String evidenceSha256,
            String evidenceSource,
            Instant observedAt
    ) throws IOException {
        try {
            return new Candidate(
                    dimension,
                    subgrain,
                    evidenceId,
                    evidenceSha256 == null ? null : evidenceSha256.trim(),
                    evidenceSource,
                    observedAt
            );
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new IOException(
                    "Persisted native evidence metadata is invalid for " + dimension,
                    exception
            );
        }
    }

    private static Candidate boundCandidate(
            EvidenceDimension dimension,
            String subgrain,
            NativeEvidenceKind nativeEvidenceKind,
            UUID evidenceId,
            String evidenceSha256,
            String evidenceSource,
            Instant observedAt,
            BindingReference bindingReference
    ) throws IOException {
        try {
            return new Candidate(
                    dimension,
                    subgrain,
                    nativeEvidenceKind,
                    evidenceId,
                    evidenceSha256 == null ? null : evidenceSha256.trim(),
                    evidenceSource,
                    observedAt,
                    bindingReference
            );
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new IOException(
                    "Persisted bound native evidence metadata is invalid for " + dimension,
                    exception
            );
        }
    }

    private static BindingReference binding(
            BindingKind bindingKind,
            UUID bindingId,
            String bindingSha256,
            String bindingSource,
            Instant recordedAt,
            String errorMessage
    ) throws IOException {
        try {
            return new BindingReference(
                    bindingKind,
                    bindingId,
                    bindingSha256 == null ? null : bindingSha256.trim(),
                    bindingSource,
                    recordedAt
            );
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new IOException(errorMessage, exception);
        }
    }

    private static String vulnerabilitySubgrain(FindingScope finding) {
        return subgrain("vulnerability", finding.vulnerabilityId().toString());
    }

    private static String assetSubgrain(FindingScope finding) {
        return subgrain("asset", finding.assetId().toString());
    }

    /** Length-prefixed components make internal semantic grouping collision-free. */
    private static String subgrain(String kind, String... components) {
        StringBuilder output = new StringBuilder(kind);
        for (String component : components) {
            String value = Objects.requireNonNull(component, "subgrain component");
            output.append('|').append(value.length()).append(':').append(value);
        }
        return output.toString();
    }

    /** Matches NETWORK_REACHABILITY_CSV_V1 and association-key normalization. */
    private static String normalizeKey(String value) {
        return Normalizer.normalize(Objects.requireNonNull(value, "value").trim(), Normalizer.Form.NFKC)
                .toLowerCase(Locale.ROOT);
    }

    private static String requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
        return value;
    }

    private static void rollback(Connection connection, Throwable cause) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            cause.addSuppressed(rollbackFailure);
        }
    }

    private record FindingScope(UUID findingId, UUID assetId, UUID vulnerabilityId) {
        private FindingScope {
            Objects.requireNonNull(findingId, "findingId");
            Objects.requireNonNull(assetId, "assetId");
            Objects.requireNonNull(vulnerabilityId, "vulnerabilityId");
        }
    }

    private record EpssCandidate(Candidate candidate, LocalDate scoreDate) {
        private EpssCandidate {
            Objects.requireNonNull(candidate, "candidate");
            Objects.requireNonNull(scoreDate, "scoreDate");
        }
    }
}
