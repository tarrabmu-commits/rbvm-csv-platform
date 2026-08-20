package io.rbvm.postgres;

import io.rbvm.decision.DecisionInputEvidenceResolver;
import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmResolvedDecisionInput;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.AssetContextEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.BusinessCriticality;
import io.rbvm.decision.RbvmResolvedDecisionInput.BusinessMissionImpactEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.Environment;
import io.rbvm.decision.RbvmResolvedDecisionInput.ExploitationProbabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ImpactDimension;
import io.rbvm.decision.RbvmResolvedDecisionInput.ImpactLevel;
import io.rbvm.decision.RbvmResolvedDecisionInput.ImpactMethod;
import io.rbvm.decision.RbvmResolvedDecisionInput.KevStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.KnownExploitationEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.KnownRansomwareCampaignUse;
import io.rbvm.decision.RbvmResolvedDecisionInput.NetworkReachabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.OriginScope;
import io.rbvm.decision.RbvmResolvedDecisionInput.ReachabilityMethod;
import io.rbvm.decision.RbvmResolvedDecisionInput.ReachabilityStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.ResolvedEvidence;
import io.rbvm.decision.RbvmResolvedDecisionInput.TechnicalSeverityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.TransportProtocol;

import java.io.IOException;
import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Resolves native immutable evidence values for exactly the references retained in one Decision
 * Input Snapshot. Resolution is UUID-addressed and provenance-checked; it never reads current views,
 * re-runs evidence selection, chooses a source winner, or calculates any decision output.
 */
public final class PostgresDecisionInputEvidenceResolver implements DecisionInputEvidenceResolver {
    private static final String TENANT_KEY = "local";
    private static final int REQUIRED_SCHEMA_VERSION = 17;

    private final JdbcConnectionFactory connections;
    private final int schemaVersion;

    public PostgresDecisionInputEvidenceResolver(
            JdbcConnectionFactory connections,
            boolean migrate
    ) throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        PostgresMigrator migrator = new PostgresMigrator(connections);
        this.schemaVersion = migrate ? migrator.migrate() : migrator.installedVersion();
        requireSchemaVersion(schemaVersion);
    }

    PostgresDecisionInputEvidenceResolver(
            JdbcConnectionFactory connections,
            int schemaVersion
    ) throws IOException {
        this.connections = Objects.requireNonNull(connections, "connections");
        this.schemaVersion = schemaVersion;
        requireSchemaVersion(schemaVersion);
    }

    @Override
    public RbvmResolvedDecisionInput resolve(RbvmDecisionInputSnapshot snapshot) throws IOException {
        Objects.requireNonNull(snapshot, "snapshot");
        if (snapshot.isV2() && schemaVersion < 20) {
            throw new IOException(
                    "Decision Input Snapshot V2 requires PostgreSQL schema version 20");
        }
        try (Connection connection = connections.open()) {
            beginReadTransaction(connection);
            try {
                UUID tenantId = requireTenant(connection);
                EnumMap<EvidenceDimension, List<ResolvedEvidence>> resolved =
                        new EnumMap<>(EvidenceDimension.class);
                for (EvidenceDimension dimension : EvidenceDimension.values()) {
                    List<ResolvedEvidence> values = new ArrayList<>();
                    for (EvidenceReference reference
                            : snapshot.dimensions().get(dimension).evidenceReferences()) {
                        values.add(resolveReference(
                                connection,
                                tenantId,
                                snapshot,
                                reference
                        ));
                    }
                    resolved.put(dimension, List.copyOf(values));
                }
                RbvmResolvedDecisionInput output = new RbvmResolvedDecisionInput(snapshot, resolved);
                connection.commit();
                return output;
            } catch (IOException | SQLException | RuntimeException exception) {
                rollback(connection, exception);
                if (exception instanceof IOException ioException) throw ioException;
                if (exception instanceof SQLException sqlException) {
                    throw PostgresErrors.sanitized(
                            "PostgreSQL Decision Input evidence resolution failed",
                            sqlException
                    );
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "Could not open PostgreSQL Decision Input evidence resolution transaction",
                    exception
            );
        }
    }

    public int schemaVersion() {
        return schemaVersion;
    }

    private static ResolvedEvidence resolveReference(
            Connection connection,
            UUID tenantId,
            RbvmDecisionInputSnapshot snapshot,
            EvidenceReference reference
    ) throws SQLException, IOException {
        return switch (reference.nativeEvidenceKind()) {
            case APPLICABILITY_ASSESSMENT ->
                    resolveApplicability(connection, tenantId, reference);
            case CVSS_V31_BASE_EVIDENCE ->
                    resolveCvss(connection, tenantId, reference);
            case CISA_KEV_EVIDENCE ->
                    resolveKev(connection, tenantId, reference);
            case EPSS_EVIDENCE ->
                    resolveEpss(connection, tenantId, reference);
            case ASSET_CONTEXT_EVIDENCE ->
                    resolveAssetContext(connection, tenantId, reference);
            case MANAGED_ASSET_REVISION ->
                    resolveManagedAssetContext(connection, tenantId, snapshot, reference);
            case NETWORK_REACHABILITY_EVIDENCE ->
                    resolveReachability(connection, tenantId, reference);
            case BUSINESS_IMPACT_EVIDENCE ->
                    resolveBusinessImpact(connection, tenantId, reference);
        };
    }

    private static ApplicabilityEvidenceValue resolveApplicability(
            Connection connection,
            UUID tenantId,
            EvidenceReference reference
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT evidence_sha256, evidence_source, evaluated_at, status, reason
                FROM rbvm.applicability_assessment
                WHERE tenant_id = ? AND id = ?
                """)) {
            bindIdentity(statement, tenantId, reference.evidenceId());
            try (ResultSet rows = statement.executeQuery()) {
                requireRow(rows, reference);
                verifyReference(reference, rows.getString(1), rows.getString(2), rows.getTimestamp(3).toInstant());
                return mapped(reference, () -> new ApplicabilityEvidenceValue(
                        reference,
                        ApplicabilityStatus.valueOf(rows.getString(4)),
                        rows.getString(5)
                ));
            }
        }
    }

    private static TechnicalSeverityEvidenceValue resolveCvss(
            Connection connection,
            UUID tenantId,
            EvidenceReference reference
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT evidence_sha256, cvss_source, observed_at,
                       cvss_version, base_score, vector
                FROM rbvm.cvss_v31_base_evidence
                WHERE tenant_id = ? AND id = ?
                """)) {
            bindIdentity(statement, tenantId, reference.evidenceId());
            try (ResultSet rows = statement.executeQuery()) {
                requireRow(rows, reference);
                verifyReference(reference, rows.getString(1), rows.getString(2), rows.getTimestamp(3).toInstant());
                return mapped(reference, () -> new TechnicalSeverityEvidenceValue(
                        reference,
                        rows.getString(4),
                        rows.getBigDecimal(5),
                        rows.getString(6)
                ));
            }
        }
    }

    private static KnownExploitationEvidenceValue resolveKev(
            Connection connection,
            UUID tenantId,
            EvidenceReference reference
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.evidence_sha256, s.kev_source, s.observed_at,
                       e.kev_status, e.kev_date_added, e.kev_due_date,
                       e.known_ransomware_campaign_use
                FROM rbvm.cisa_kev_evidence e
                JOIN rbvm.cisa_kev_catalog_snapshot s
                  ON s.tenant_id = e.tenant_id AND s.id = e.snapshot_id
                WHERE e.tenant_id = ? AND e.id = ?
                """)) {
            bindIdentity(statement, tenantId, reference.evidenceId());
            try (ResultSet rows = statement.executeQuery()) {
                requireRow(rows, reference);
                verifyReference(reference, rows.getString(1), rows.getString(2), rows.getTimestamp(3).toInstant());
                KevStatus status = enumValue(KevStatus.class, rows.getString(4), reference);
                LocalDate dateAdded = rows.getObject(5, LocalDate.class);
                LocalDate dueDate = rows.getObject(6, LocalDate.class);
                String ransomware = rows.getString(7);
                KnownRansomwareCampaignUse use = ransomware == null
                        ? null
                        : enumValue(KnownRansomwareCampaignUse.class, ransomware, reference);
                return mapped(reference, () -> new KnownExploitationEvidenceValue(
                        reference,
                        status,
                        dateAdded,
                        dueDate,
                        use
                ));
            }
        }
    }

    private static ExploitationProbabilityEvidenceValue resolveEpss(
            Connection connection,
            UUID tenantId,
            EvidenceReference reference
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.evidence_sha256, s.epss_source, s.observed_at,
                       e.epss_probability, e.epss_percentile,
                       s.model_version, s.score_date
                FROM rbvm.epss_evidence e
                JOIN rbvm.epss_score_snapshot s
                  ON s.tenant_id = e.tenant_id AND s.id = e.snapshot_id
                WHERE e.tenant_id = ? AND e.id = ?
                """)) {
            bindIdentity(statement, tenantId, reference.evidenceId());
            try (ResultSet rows = statement.executeQuery()) {
                requireRow(rows, reference);
                verifyReference(reference, rows.getString(1), rows.getString(2), rows.getTimestamp(3).toInstant());
                return mapped(reference, () -> new ExploitationProbabilityEvidenceValue(
                        reference,
                        rows.getBigDecimal(4),
                        rows.getBigDecimal(5),
                        rows.getString(6),
                        rows.getObject(7, LocalDate.class)
                ));
            }
        }
    }

    private static AssetContextEvidenceValue resolveAssetContext(
            Connection connection,
            UUID tenantId,
            EvidenceReference reference
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.evidence_sha256, s.context_source, s.observed_at,
                       e.environment, e.business_service, e.business_owner,
                       e.business_criticality
                FROM rbvm.asset_context_evidence e
                JOIN rbvm.asset_context_snapshot s
                  ON s.tenant_id = e.tenant_id AND s.id = e.snapshot_id
                WHERE e.tenant_id = ? AND e.id = ?
                """)) {
            bindIdentity(statement, tenantId, reference.evidenceId());
            try (ResultSet rows = statement.executeQuery()) {
                requireRow(rows, reference);
                verifyReference(reference, rows.getString(1), rows.getString(2), rows.getTimestamp(3).toInstant());
                Environment environment = enumValue(Environment.class, rows.getString(4), reference);
                BusinessCriticality criticality = enumValue(
                        BusinessCriticality.class,
                        rows.getString(7),
                        reference
                );
                return mapped(reference, () -> new AssetContextEvidenceValue(
                        reference,
                        environment,
                        rows.getString(5),
                        rows.getString(6),
                        criticality
                ));
            }
        }
    }

    private static AssetContextEvidenceValue resolveManagedAssetContext(
            Connection connection,
            UUID tenantId,
            RbvmDecisionInputSnapshot snapshot,
            EvidenceReference reference
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT managed_asset_id, evidence_sha256, context_source, recorded_at,
                       environment, business_service, business_owner, business_criticality
                FROM rbvm.managed_asset_revision
                WHERE tenant_id = ? AND id = ?
                """)) {
            bindIdentity(statement, tenantId, reference.evidenceId());
            try (ResultSet rows = statement.executeQuery()) {
                requireRow(rows, reference);
                UUID managedAssetId = rows.getObject(1, UUID.class);
                verifyReference(
                        reference,
                        rows.getString(2),
                        rows.getString(3),
                        rows.getTimestamp(4).toInstant()
                );
                verifyManagedAssetBinding(
                        connection,
                        tenantId,
                        snapshot,
                        reference,
                        managedAssetId
                );
                Environment environment = enumValue(
                        Environment.class,
                        rows.getString(5),
                        reference
                );
                BusinessCriticality criticality = enumValue(
                        BusinessCriticality.class,
                        rows.getString(8),
                        reference
                );
                return mapped(reference, () -> new AssetContextEvidenceValue(
                        reference,
                        environment,
                        rows.getString(6),
                        rows.getString(7),
                        criticality
                ));
            }
        }
    }

    private static void verifyManagedAssetBinding(
            Connection connection,
            UUID tenantId,
            RbvmDecisionInputSnapshot snapshot,
            EvidenceReference reference,
            UUID managedAssetId
    ) throws SQLException, IOException {
        BindingReference binding = Objects.requireNonNull(
                reference.bindingReference(),
                "managed asset reference binding"
        );
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT evidence_sha256, link_method, recorded_at,
                       scanner_asset_id, link_status, managed_asset_id
                FROM rbvm.scanner_managed_asset_link_event
                WHERE tenant_id = ? AND id = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, binding.bindingId());
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new IOException(
                            "Decision Input managed-asset binding does not resolve to native link event");
                }
                String linkSha = rows.getString(1);
                String linkMethod = rows.getString(2);
                java.time.Instant linkRecordedAt = rows.getTimestamp(3).toInstant();
                UUID scannerAssetId = rows.getObject(4, UUID.class);
                String linkStatus = rows.getString(5);
                UUID linkManagedAssetId = rows.getObject(6, UUID.class);
                if (!Objects.equals(binding.bindingSha256(),
                                linkSha == null ? null : linkSha.trim())
                        || !Objects.equals(binding.bindingSource(), linkMethod)
                        || !Objects.equals(binding.recordedAt(), linkRecordedAt)
                        || !"LINKED".equals(linkStatus)
                        || !Objects.equals(managedAssetId, linkManagedAssetId)) {
                    throw new IOException(
                            "Decision Input managed-asset binding provenance does not match native link event");
                }
                UUID findingAssetId = requireFindingAsset(
                        connection,
                        tenantId,
                        snapshot.findingId()
                );
                if (!Objects.equals(scannerAssetId, findingAssetId)) {
                    throw new IOException(
                            "Decision Input managed-asset binding does not belong to snapshot Finding asset");
                }
            }
        }
    }

    private static UUID requireFindingAsset(
            Connection connection,
            UUID tenantId,
            UUID findingId
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT asset_id
                FROM rbvm.exposure
                WHERE tenant_id = ? AND id = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, findingId);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    throw new IOException(
                            "Decision Input snapshot Finding_ID no longer resolves");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static NetworkReachabilityEvidenceValue resolveReachability(
            Connection connection,
            UUID tenantId,
            EvidenceReference reference
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.evidence_sha256, s.evidence_source, s.observed_at,
                       e.origin_scope, e.origin_label, e.transport_protocol,
                       e.target_port, e.target_service,
                       e.reachability_status, e.reachability_method
                FROM rbvm.network_reachability_evidence e
                JOIN rbvm.network_reachability_snapshot s
                  ON s.tenant_id = e.tenant_id AND s.id = e.snapshot_id
                WHERE e.tenant_id = ? AND e.id = ?
                """)) {
            bindIdentity(statement, tenantId, reference.evidenceId());
            try (ResultSet rows = statement.executeQuery()) {
                requireRow(rows, reference);
                verifyReference(reference, rows.getString(1), rows.getString(2), rows.getTimestamp(3).toInstant());
                OriginScope originScope = enumValue(OriginScope.class, rows.getString(4), reference);
                TransportProtocol protocol = enumValue(
                        TransportProtocol.class,
                        rows.getString(6),
                        reference
                );
                Object portValue = rows.getObject(7);
                Integer targetPort = portValue == null ? null : ((Number) portValue).intValue();
                ReachabilityStatus status = enumValue(
                        ReachabilityStatus.class,
                        rows.getString(9),
                        reference
                );
                ReachabilityMethod method = enumValue(
                        ReachabilityMethod.class,
                        rows.getString(10),
                        reference
                );
                return mapped(reference, () -> new NetworkReachabilityEvidenceValue(
                        reference,
                        originScope,
                        rows.getString(5),
                        protocol,
                        targetPort,
                        rows.getString(8),
                        status,
                        method
                ));
            }
        }
    }

    private static BusinessMissionImpactEvidenceValue resolveBusinessImpact(
            Connection connection,
            UUID tenantId,
            EvidenceReference reference
    ) throws SQLException, IOException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.evidence_sha256, s.impact_source, s.observed_at,
                       e.business_service, e.business_service_normalized,
                       e.impact_dimension, e.impact_level,
                       e.impact_method, e.impact_statement
                FROM rbvm.business_impact_evidence e
                JOIN rbvm.business_impact_snapshot s
                  ON s.tenant_id = e.tenant_id AND s.id = e.snapshot_id
                WHERE e.tenant_id = ? AND e.id = ?
                """)) {
            bindIdentity(statement, tenantId, reference.evidenceId());
            try (ResultSet rows = statement.executeQuery()) {
                requireRow(rows, reference);
                verifyReference(reference, rows.getString(1), rows.getString(2), rows.getTimestamp(3).toInstant());
                ImpactDimension dimension = enumValue(
                        ImpactDimension.class,
                        rows.getString(6),
                        reference
                );
                ImpactLevel level = enumValue(ImpactLevel.class, rows.getString(7), reference);
                ImpactMethod method = enumValue(ImpactMethod.class, rows.getString(8), reference);
                return mapped(reference, () -> new BusinessMissionImpactEvidenceValue(
                        reference,
                        rows.getString(4),
                        rows.getString(5),
                        dimension,
                        level,
                        method,
                        rows.getString(9)
                ));
            }
        }
    }

    private static void bindIdentity(
            PreparedStatement statement,
            UUID tenantId,
            UUID evidenceId
    ) throws SQLException {
        statement.setObject(1, tenantId);
        statement.setObject(2, evidenceId);
    }

    private static void requireRow(ResultSet rows, EvidenceReference reference)
            throws SQLException, IOException {
        if (!rows.next()) {
            throw new IOException(
                    "Decision Input evidence reference does not resolve to native immutable evidence: "
                            + reference.dimension() + "/" + reference.evidenceId()
            );
        }
    }

    private static void verifyReference(
            EvidenceReference reference,
            String evidenceSha256,
            String evidenceSource,
            java.time.Instant observedAt
    ) throws IOException {
        String normalizedSha = evidenceSha256 == null ? null : evidenceSha256.trim();
        if (!Objects.equals(reference.evidenceSha256(), normalizedSha)
                || !Objects.equals(reference.evidenceSource(), evidenceSource)
                || !Objects.equals(reference.observedAt(), observedAt)) {
            throw new IOException(
                    "Decision Input native evidence provenance does not match snapshot reference: "
                            + reference.dimension() + "/" + reference.evidenceId()
            );
        }
    }

    private static <E extends Enum<E>> E enumValue(
            Class<E> type,
            String value,
            EvidenceReference reference
    ) throws IOException {
        try {
            return Enum.valueOf(type, value);
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new IOException(
                    "Persisted native evidence enum is invalid for "
                            + reference.dimension() + "/" + reference.evidenceId(),
                    exception
            );
        }
    }

    private static <T extends ResolvedEvidence> T mapped(
            EvidenceReference reference,
            Mapping<T> mapping
    ) throws IOException, SQLException {
        try {
            return mapping.map();
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new IOException(
                    "Persisted native evidence value is invalid for "
                            + reference.dimension() + "/" + reference.evidenceId(),
                    exception
            );
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
                            "PostgreSQL projection tenant has not been initialized before Decision Input evidence resolution");
                }
                return rows.getObject(1, UUID.class);
            }
        }
    }

    private static void requireSchemaVersion(int schemaVersion) throws IOException {
        if (schemaVersion < REQUIRED_SCHEMA_VERSION) {
            throw new IOException(
                    "PostgreSQL schema version " + schemaVersion
                            + " is older than required version " + REQUIRED_SCHEMA_VERSION
            );
        }
    }

    private static void rollback(Connection connection, Throwable cause) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            cause.addSuppressed(rollbackFailure);
        }
    }

    @FunctionalInterface
    private interface Mapping<T extends ResolvedEvidence> {
        T map() throws SQLException;
    }
}
