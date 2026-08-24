package io.rbvm.postgres;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Derives resumable NVD bootstrap coverage from exact successful V30 annual-feed runs. */
public final class PostgresPublicIntelligenceNvdBootstrapStateReader
        implements PublicIntelligenceNvdBootstrapStateReader {
    private static final Pattern ANNUAL_URI = Pattern.compile(
            "^https://nvd\\.nist\\.gov/feeds/json/cve/2\\.0/"
                    + "nvdcve-2\\.0-(20[0-9]{2})\\.json\\.gz$");
    private static final String SQL = """
            SELECT source_uri
            FROM rbvm.public_intelligence_sync_run
            WHERE provider = 'NVD'
              AND status = 'COMPLETE'
            ORDER BY completed_at, id
            """;

    private final JdbcConnectionFactory connections;

    public PostgresPublicIntelligenceNvdBootstrapStateReader(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    @Override
    public Set<Integer> completedAnnualYears() throws IOException {
        LinkedHashSet<Integer> years = new LinkedHashSet<>();
        try (Connection connection = connections.open();
             PreparedStatement statement = connection.prepareStatement(SQL);
             ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                String uri = result.getString(1);
                if (uri == null) continue;
                Matcher matcher = ANNUAL_URI.matcher(uri);
                if (matcher.matches()) years.add(Integer.parseInt(matcher.group(1)));
            }
            return Collections.unmodifiableSet(years);
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("read NVD bootstrap coverage", exception);
        }
    }
}
