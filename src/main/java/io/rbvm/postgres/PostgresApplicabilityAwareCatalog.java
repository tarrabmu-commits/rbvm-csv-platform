package io.rbvm.postgres;

import io.rbvm.domain.CaseActionCommand;
import io.rbvm.domain.CaseAuditEvent;
import io.rbvm.domain.CasePage;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.CatalogSnapshot;
import io.rbvm.domain.DomainCatalog;
import io.rbvm.domain.DomainMaterializationResult;
import io.rbvm.domain.PreparedCaseAction;

import java.io.IOException;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Read decorator that surfaces V9 applicability evidence on normal case exposure reads.
 *
 * <p>The existing public exposure ID remains unchanged. A separate {@code findingId} UUID is added
 * because APPLICABILITY_CSV_V1 intentionally binds to {@code rbvm.exposure.id}, not the hashed
 * exposure public identifier.</p>
 */
public final class PostgresApplicabilityAwareCatalog implements DomainCatalog {
    private static final String TENANT_KEY = "local";

    private final DomainCatalog delegate;
    private final JdbcConnectionFactory connections;

    public PostgresApplicabilityAwareCatalog(
            DomainCatalog delegate,
            JdbcConnectionFactory connections
    ) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    @Override
    public String backend() {
        return delegate.backend();
    }

    @Override
    public DomainMaterializationResult materialize(
            UUID importId,
            Path csvPath,
            String sourceProfileId,
            String contractId
    ) throws IOException {
        return delegate.materialize(importId, csvPath, sourceProfileId, contractId);
    }

    @Override
    public CatalogSnapshot snapshot() {
        return delegate.snapshot();
    }

    @Override
    public CasePage queryCases(CaseQuery query) {
        return delegate.queryCases(query);
    }

    @Override
    public Optional<Map<String, Object>> caseDetail(String caseId) {
        Optional<Map<String, Object>> base = delegate.caseDetail(caseId);
        if (base.isEmpty()) {
            return base;
        }
        Map<String, Object> output = new LinkedHashMap<>(base.orElseThrow());
        Object rawExposures = output.get("exposures");
        if (!(rawExposures instanceof List<?> exposures)) {
            return Optional.of(immutableNullableMap(output));
        }
        try (Connection connection = connections.open()) {
            UUID tenantId = tenantId(connection);
            if (tenantId == null) {
                return Optional.of(immutableNullableMap(output));
            }
            List<Map<String, Object>> enriched = new ArrayList<>(exposures.size());
            for (Object raw : exposures) {
                if (!(raw instanceof Map<?, ?> source)) {
                    continue;
                }
                Map<String, Object> exposure = stringKeyCopy(source);
                Object publicId = exposure.get("exposureId");
                if (publicId != null) {
                    enrichExposure(connection, tenantId, publicId.toString(), exposure);
                }
                enriched.add(immutableNullableMap(exposure));
            }
            output.put("exposures", List.copyOf(enriched));
            return Optional.of(immutableNullableMap(output));
        } catch (SQLException exception) {
            throw new IllegalStateException(
                    "PostgreSQL applicability read failed: " + PostgresErrors.safeMessage(exception)
            );
        }
    }

    @Override
    public PreparedCaseAction prepareCaseAction(
            long sequence,
            String caseId,
            CaseActionCommand command,
            String idempotencyKey,
            String actorId,
            String actorAssurance,
            Instant occurredAt
    ) {
        return delegate.prepareCaseAction(
                sequence,
                caseId,
                command,
                idempotencyKey,
                actorId,
                actorAssurance,
                occurredAt
        );
    }

    @Override
    public Map<String, Object> applyCaseEvent(CaseAuditEvent event) {
        return delegate.applyCaseEvent(event);
    }

    @Override
    public boolean isMaterialized(UUID importId) {
        return delegate.isMaterialized(importId);
    }

    private static void enrichExposure(
            Connection connection,
            UUID tenantId,
            String exposurePublicId,
            Map<String, Object> output
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT f.finding_id, f.applicability_status, f.applicability_assessed,
                       f.applicability_reason, f.applicability_evidence_source,
                       f.applicability_evaluated_at
                FROM rbvm.finding_applicability f
                JOIN rbvm.exposure e
                  ON e.tenant_id = f.tenant_id AND e.id = f.finding_id
                WHERE f.tenant_id = ? AND e.public_id = ?
                """)) {
            statement.setObject(1, tenantId);
            statement.setString(2, exposurePublicId);
            try (ResultSet rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return;
                }
                output.put("findingId", rows.getObject("finding_id", UUID.class).toString());
                output.put("applicabilityStatus", rows.getString("applicability_status"));
                output.put("applicabilityAssessed", rows.getBoolean("applicability_assessed"));
                output.put("applicabilityReason", rows.getString("applicability_reason"));
                output.put("applicabilityEvidenceSource",
                        rows.getString("applicability_evidence_source"));
                Timestamp evaluatedAt = rows.getTimestamp("applicability_evaluated_at");
                output.put("applicabilityEvaluatedAt",
                        evaluatedAt == null ? null : evaluatedAt.toInstant().toString());
            }
        }
    }

    private static UUID tenantId(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT id FROM rbvm.tenant WHERE tenant_key = ?")) {
            statement.setString(1, TENANT_KEY);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getObject(1, UUID.class) : null;
            }
        }
    }

    private static Map<String, Object> stringKeyCopy(Map<?, ?> source) {
        Map<String, Object> output = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (entry.getKey() instanceof String key) {
                output.put(key, entry.getValue());
            }
        }
        return output;
    }

    private static Map<String, Object> immutableNullableMap(Map<String, Object> source) {
        return Collections.unmodifiableMap(new LinkedHashMap<>(source));
    }
}
