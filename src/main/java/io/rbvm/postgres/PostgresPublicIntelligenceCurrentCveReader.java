package io.rbvm.postgres;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/** PostgreSQL implementation used to derive tombstones only from complete-snapshot providers. */
public final class PostgresPublicIntelligenceCurrentCveReader
        implements PublicIntelligenceCurrentCveReader {
    private final JdbcConnectionFactory connections;

    public PostgresPublicIntelligenceCurrentCveReader(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    @Override
    public Set<String> currentCves(PostgresPublicIntelligenceStore.Provider provider)
            throws IOException {
        Objects.requireNonNull(provider, "provider");
        LinkedHashSet<String> result = new LinkedHashSet<>();
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT cve_id
                     FROM rbvm.current_public_intelligence_record
                     WHERE provider = ?
                     ORDER BY cve_id
                     """)) {
            statement.setString(1, provider.name());
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) result.add(rows.getString(1));
            }
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized(
                    "PostgreSQL current public-intelligence CVE read failed", exception);
        }
        return Set.copyOf(result);
    }
}
