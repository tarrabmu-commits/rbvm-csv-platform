package io.rbvm.postgres;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Objects;
import java.util.UUID;

/** PostgreSQL-backed reference export for constructing APPLICABILITY_CSV_V1 assessments safely. */
public final class PostgresApplicabilityFindingExporter implements ApplicabilityFindingExporter {
    private static final String TENANT_KEY = "local";

    private final JdbcConnectionFactory connections;

    public PostgresApplicabilityFindingExporter(JdbcConnectionFactory connections) {
        this.connections = Objects.requireNonNull(connections, "connections");
    }

    @Override
    public byte[] exportCsv() throws IOException {
        StringBuilder output = new StringBuilder();
        output.append("Finding_ID,Agent,CVE_ID,Affected_Product,Severity,")
                .append("Current_Applicability_Status,Current_Applicability_Assessed,")
                .append("Current_Applicability_Reason,Current_Evidence_Source,Current_Evaluated_At\r\n");
        try (Connection connection = connections.open()) {
            UUID tenantId = tenantId(connection);
            if (tenantId == null) {
                return output.toString().getBytes(StandardCharsets.UTF_8);
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT finding_id, asset_name, cve_id, product_name, current_severity,
                           applicability_status, applicability_assessed, applicability_reason,
                           applicability_evidence_source, applicability_evaluated_at
                    FROM rbvm.finding_applicability
                    WHERE tenant_id = ?
                    ORDER BY cve_id, asset_name, product_name, finding_id
                    """)) {
                statement.setObject(1, tenantId);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        append(output, rows.getObject("finding_id", UUID.class).toString());
                        append(output, rows.getString("asset_name"));
                        append(output, rows.getString("cve_id"));
                        append(output, rows.getString("product_name"));
                        append(output, rows.getString("current_severity"));
                        append(output, rows.getString("applicability_status"));
                        append(output, Boolean.toString(rows.getBoolean("applicability_assessed")));
                        append(output, rows.getString("applicability_reason"));
                        append(output, rows.getString("applicability_evidence_source"));
                        Timestamp evaluatedAt = rows.getTimestamp("applicability_evaluated_at");
                        appendLast(output, evaluatedAt == null ? "" : evaluatedAt.toInstant().toString());
                    }
                }
            }
            return output.toString().getBytes(StandardCharsets.UTF_8);
        } catch (SQLException exception) {
            throw PostgresErrors.sanitized("Could not export applicability finding references", exception);
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
        if (!quote) {
            return normalized;
        }
        return '"' + normalized.replace("\"", "\"\"") + '"';
    }
}
