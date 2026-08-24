package io.rbvm.postgres;

import io.rbvm.csv.VulnerabilityIntelligenceEvidence;
import io.rbvm.csv.WazuhObservation;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

final class PostgresCanonicalProjectionMutationBuffer {
    private final UUID tenantId;
    private final Instant now;
    private final Map<UUID, AssetMutation> assets = new LinkedHashMap<>();
    private final Map<UUID, VulnerabilityMutation> vulnerabilities = new LinkedHashMap<>();

    PostgresCanonicalProjectionMutationBuffer(UUID tenantId, Instant now) {
        this.tenantId = tenantId;
        this.now = now;
    }

    void observeAsset(
            UUID id,
            String publicId,
            boolean createdThisCall,
            WazuhObservation observation
    ) {
        AssetMutation current = assets.get(id);
        if (current == null) {
            assets.put(id, new AssetMutation(
                    id,
                    publicId,
                    observation.detectedAt(),
                    observation.detectedAt(),
                    observation.agentObservedName(),
                    observation.osNameRaw(),
                    !createdThisCall
            ));
            return;
        }
        Instant first = observation.detectedAt().isBefore(current.firstObservedAt())
                ? observation.detectedAt() : current.firstObservedAt();
        Instant latest = current.latestObservedAt();
        String observedName = current.observedName();
        String osNameRaw = current.osNameRaw();
        if (observation.detectedAt().isAfter(latest)) {
            latest = observation.detectedAt();
            observedName = observation.agentObservedName();
            osNameRaw = observation.osNameRaw();
        }
        assets.put(id, new AssetMutation(
                id,
                publicId,
                first,
                latest,
                observedName,
                osNameRaw,
                true
        ));
    }

    void observeVulnerability(
            UUID id,
            boolean createdThisCall,
            WazuhObservation observation
    ) {
        VulnerabilityMutation current = vulnerabilities.get(id);
        String description = null;
        Instant descriptionAt = null;
        VulnerabilityIntelligenceEvidence intelligence = null;
        boolean dirty = !createdThisCall;
        if (current != null) {
            description = current.description();
            descriptionAt = current.descriptionAt();
            intelligence = current.intelligence();
            dirty = true;
        }
        if (!observation.descriptionSnapshot().isBlank()
                && (descriptionAt == null || observation.detectedAt().isAfter(descriptionAt))) {
            description = observation.descriptionSnapshot();
            descriptionAt = observation.detectedAt();
        }
        VulnerabilityIntelligenceEvidence observedIntelligence = observation.intelligence();
        if (observedIntelligence != null
                && (intelligence == null
                || observedIntelligence.observedAt().isAfter(intelligence.observedAt()))) {
            intelligence = observedIntelligence;
        }
        vulnerabilities.put(id, new VulnerabilityMutation(
                id,
                description,
                descriptionAt,
                intelligence,
                dirty
        ));
    }

    void flush(Connection connection) throws SQLException {
        flushAssets(connection);
        flushVulnerabilities(connection);
    }

    private void flushAssets(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE rbvm.asset SET
                    public_id = ?,
                    first_observed_at = LEAST(first_observed_at, ?),
                    observed_name = CASE WHEN ? > last_observed_at THEN ? ELSE observed_name END,
                    os_name_raw = CASE WHEN ? > last_observed_at THEN ? ELSE os_name_raw END,
                    last_observed_at = GREATEST(last_observed_at, ?),
                    updated_at = ?
                WHERE tenant_id = ? AND id = ?
                """)) {
            for (AssetMutation mutation : assets.values()) {
                if (!mutation.dirty()) {
                    continue;
                }
                statement.setString(1, mutation.publicId());
                setInstant(statement, 2, mutation.firstObservedAt());
                setInstant(statement, 3, mutation.latestObservedAt());
                statement.setString(4, mutation.observedName());
                setInstant(statement, 5, mutation.latestObservedAt());
                statement.setString(6, mutation.osNameRaw());
                setInstant(statement, 7, mutation.latestObservedAt());
                setInstant(statement, 8, now);
                statement.setObject(9, tenantId);
                statement.setObject(10, mutation.id());
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    private void flushVulnerabilities(Connection connection) throws SQLException {
        try (PreparedStatement description = connection.prepareStatement("""
                UPDATE rbvm.vulnerability SET
                    description_current = CASE
                        WHEN length(?) > 0 AND
                             (description_observed_at IS NULL OR ? > description_observed_at)
                        THEN ? ELSE description_current END,
                    description_observed_at = CASE
                        WHEN length(?) > 0 AND
                             (description_observed_at IS NULL OR ? > description_observed_at)
                        THEN ? ELSE description_observed_at END
                WHERE id = ?
                """);
             PreparedStatement intelligence = connection.prepareStatement("""
                UPDATE rbvm.vulnerability SET
                    cvss_version = ?, cvss_base_score = ?, cvss_vector = ?,
                    epss_probability = ?, epss_percentile = ?, known_exploited = ?,
                    kev_date_added = ?, kev_due_date = ?, intelligence_observed_at = ?,
                    intelligence_source_references = ?, priority_tier = ?
                WHERE id = ? AND (intelligence_observed_at IS NULL
                    OR ? > intelligence_observed_at)
                """)) {
            boolean hasDescriptions = false;
            boolean hasIntelligence = false;
            for (VulnerabilityMutation mutation : vulnerabilities.values()) {
                if (!mutation.dirty()) {
                    continue;
                }
                if (mutation.descriptionAt() != null) {
                    description.setString(1, mutation.description());
                    setInstant(description, 2, mutation.descriptionAt());
                    description.setString(3, mutation.description());
                    description.setString(4, mutation.description());
                    setInstant(description, 5, mutation.descriptionAt());
                    setInstant(description, 6, mutation.descriptionAt());
                    description.setObject(7, mutation.id());
                    description.addBatch();
                    hasDescriptions = true;
                }
                VulnerabilityIntelligenceEvidence value = mutation.intelligence();
                if (value != null) {
                    intelligence.setObject(1, value.cvssVersion());
                    intelligence.setObject(2, value.cvssBaseScore());
                    intelligence.setObject(3, value.cvssVector());
                    intelligence.setObject(4, value.epssProbability());
                    intelligence.setObject(5, value.epssPercentile());
                    intelligence.setObject(6, value.knownExploited());
                    intelligence.setObject(7, value.kevDateAdded());
                    intelligence.setObject(8, value.kevDueDate());
                    setInstant(intelligence, 9, value.observedAt());
                    intelligence.setObject(10, value.sourceReferences());
                    intelligence.setObject(11, value.priorityTier());
                    intelligence.setObject(12, mutation.id());
                    setInstant(intelligence, 13, value.observedAt());
                    intelligence.addBatch();
                    hasIntelligence = true;
                }
            }
            if (hasDescriptions) {
                description.executeBatch();
            }
            if (hasIntelligence) {
                intelligence.executeBatch();
            }
        }
    }

    private static void setInstant(PreparedStatement statement, int index, Instant value)
            throws SQLException {
        statement.setTimestamp(index, Timestamp.from(value));
    }

    private record AssetMutation(
            UUID id,
            String publicId,
            Instant firstObservedAt,
            Instant latestObservedAt,
            String observedName,
            String osNameRaw,
            boolean dirty
    ) {
    }

    private record VulnerabilityMutation(
            UUID id,
            String description,
            Instant descriptionAt,
            VulnerabilityIntelligenceEvidence intelligence,
            boolean dirty
    ) {
    }
}
