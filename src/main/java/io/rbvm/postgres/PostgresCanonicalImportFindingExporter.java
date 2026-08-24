package io.rbvm.postgres;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** PostgreSQL exact import -> observation -> exposure(Finding) manifest export. */
public final class PostgresCanonicalImportFindingExporter implements CanonicalImportFindingExporter {
    private static final String TENANT_KEY = "local";
    private final JdbcConnectionFactory connections;

    public PostgresCanonicalImportFindingExporter(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    @Override
    public Optional<byte[]> exportCsv(UUID importId) throws IOException {
        Objects.requireNonNull(importId, "importId");
        try (Connection connection = connections.open()) {
            if (!importExists(connection, importId)) return Optional.empty();
            StringBuilder output = new StringBuilder();
            output.append("Import_ID,Finding_ID,Source_Row_Number,Source_Profile_Key,Agent,CVE_ID,")
                    .append("Affected_Product,Finding_Status,Severity\r\n");
            try (PreparedStatement statement = connection.prepareStatement("""
          SELECT e.id AS finding_id,
                 MIN(io.source_row_number) AS source_row_number,
                 sp.external_key AS source_profile_key,
                 a.observed_name AS asset_name,
                 v.cve_id,
                 ac.observed_product_name AS product_name,
                 e.status AS finding_status,
                 e.current_severity
          FROM rbvm.import_observation io
          JOIN rbvm.import_run ir
            ON ir.tenant_id = io.tenant_id AND ir.id = io.import_id
          JOIN rbvm.source_profile sp
            ON sp.tenant_id = ir.tenant_id AND sp.id = ir.source_profile_id
          JOIN rbvm.tenant t
            ON t.id = ir.tenant_id
          JOIN LATERAL (
              SELECT link.exposure_id
              FROM rbvm.exposure_observation link
              WHERE link.tenant_id = io.tenant_id
                AND link.observation_id = io.observation_id
              OFFSET 0
          ) eo ON true
          JOIN LATERAL (
              SELECT x.id, x.asset_id, x.vulnerability_id, x.component_id,
                     x.status, x.current_severity
              FROM rbvm.exposure x
              WHERE x.tenant_id = io.tenant_id
                AND x.id = eo.exposure_id
              OFFSET 0
          ) e ON true
          JOIN LATERAL (
              SELECT x.observed_name
              FROM rbvm.asset x
              WHERE x.tenant_id = io.tenant_id AND x.id = e.asset_id
              OFFSET 0
          ) a ON true
          JOIN LATERAL (
              SELECT x.cve_id
              FROM rbvm.vulnerability x
              WHERE x.id = e.vulnerability_id
              OFFSET 0
          ) v ON true
          JOIN LATERAL (
              SELECT x.observed_product_name
              FROM rbvm.asset_component x
              WHERE x.tenant_id = io.tenant_id AND x.id = e.component_id
              OFFSET 0
          ) ac ON true
          WHERE io.import_id = ? AND t.tenant_key = ?
          GROUP BY e.id, sp.external_key, a.observed_name, v.cve_id,
                   ac.observed_product_name, e.status, e.current_severity
          ORDER BY MIN(io.source_row_number), e.id
          """)) {
                statement.setObject(1, importId);
                statement.setString(2, TENANT_KEY);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        append(output, importId.toString());
                        append(output, rows.getObject("finding_id", UUID.class).toString());
                        append(output, Long.toString(rows.getLong("source_row_number")));
                        append(output, rows.getString("source_profile_key"));
                        append(output, rows.getString("asset_name"));
                        append(output, rows.getString("cve_id"));
                        append(output, rows.getString("product_name"));
                        append(output, rows.getString("finding_status"));
                        appendLast(output, rows.getString("current_severity"));
                    }
                }
            }
            return Optional.of(output.toString().getBytes(StandardCharsets.UTF_8));
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("Could not export canonical import Finding manifest", exception);
        }
    }

    private static boolean importExists(Connection connection, UUID importId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT 1
                FROM rbvm.import_run ir
                JOIN rbvm.tenant t ON t.id = ir.tenant_id
                WHERE ir.id = ? AND t.tenant_key = ? AND ir.status = 'COMPLETED'
                """)) {
            statement.setObject(1, importId);
            statement.setString(2, TENANT_KEY);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next();
            }
        }
    }

    private static void append(StringBuilder output, String value) {
        output.append(csv(value)).append(',');
    }

    private static void appendLast(StringBuilder output, String value) {
        output.append(csv(value)).append("\r\n");
    }

    private static String csv(String value) {
        String normalized = value == null ? "" : value;
        boolean quote = normalized.indexOf(',') >= 0
                || normalized.indexOf('"') >= 0
                || normalized.indexOf('\r') >= 0
                || normalized.indexOf('\n') >= 0;
        return quote ? '"' + normalized.replace("\"", "\"\"") + '"' : normalized;
    }
}
