package io.rbvm.postgres;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import java.util.UUID;

/** PostgreSQL proof that a CISA KEV V30 source completed through the V31 validated sync lifecycle. */
public final class PostgresCisaKevCatalogValidationReader implements CisaKevCatalogValidationReader {
    private static final String OFFICIAL_CISA_KEV_URI =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    private final JdbcConnectionFactory connections;

    public PostgresCisaKevCatalogValidationReader(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    @Override
    public boolean isCompleteValidatedCatalog(UUID syncRunId) throws IOException {
        Objects.requireNonNull(syncRunId, "syncRunId");
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT EXISTS (
                         SELECT 1
                         FROM rbvm.public_intelligence_sync_run r
                         JOIN rbvm.public_intelligence_sync_job j
                           ON j.sync_run_id = r.id
                          AND j.provider = r.provider
                         WHERE r.id = ?
                           AND r.provider = 'CISA_KEV'
                           AND r.status = 'COMPLETE'
                           AND r.source_uri = ?
                           AND j.status = 'COMPLETE'
                           AND j.stage = 'COMPLETE'
                     )
                     """)) {
            statement.setObject(1, syncRunId);
            statement.setString(2, OFFICIAL_CISA_KEV_URI);
            try (ResultSet rows = statement.executeQuery()) {
                rows.next();
                return rows.getBoolean(1);
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "PostgreSQL validated CISA KEV catalog proof failed", exception);
        }
    }
}
