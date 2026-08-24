package io.rbvm.postgres;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class PostgresMigratorSelfTest {
    private static final int LATEST_SCHEMA_VERSION = 31;

    private PostgresMigratorSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        appliesAndReplaysVersionedMigrations();
        rejectsChecksumDrift();
        rollsBackFailedMigration();
        System.out.println("PostgresMigratorSelfTest: PASS");
    }

    private static void appliesAndReplaysVersionedMigrations() throws Exception {
        FakeDatabase database = new FakeDatabase();
        PostgresMigrator migrator = new PostgresMigrator(database::connection);
        assert migrator.migrate() == LATEST_SCHEMA_VERSION;
        assert database.checksums.size() == LATEST_SCHEMA_VERSION;
        assert database.commits == LATEST_SCHEMA_VERSION;
        assert database.rollbacks == 0;
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.observation"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.operational_finding"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.applicability_assessment"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_applicability"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.cvss_v31_base_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_cvss_v31_base_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_cvss_v31_base_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.cisa_kev_catalog_snapshot"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.cisa_kev_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_cisa_kev_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_cisa_kev_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.epss_score_snapshot"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.epss_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_epss_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_epss_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.asset_context_snapshot"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.asset_context_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_asset_context_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_asset_context_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_snapshot"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_network_reachability_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_network_reachability_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.business_impact_snapshot"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.business_impact_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_business_impact_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_business_impact_evidence"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.decision_methodology_policy"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.decision_methodology_evidence_policy"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.decision_methodology_source_allowlist"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.decision_input_snapshot"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.decision_input_dimension"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.decision_input_evidence_reference"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.managed_asset ("));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.managed_asset_revision"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_managed_asset"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.scanner_managed_asset_link_event"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_scanner_managed_asset_link"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.active_scanner_managed_asset_link"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.finding_reachability_scope_link_event"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_finding_reachability_scope_link"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.finding_business_service_link_event"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_finding_business_service_link"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("RBVM_DECISION_INPUT_SNAPSHOT_V3"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("FINDING_REACHABILITY_SCOPE_LINK_EVENT"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("FINDING_BUSINESS_SERVICE_LINK_EVENT"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.formula_result"));
        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.derived_risk_result"));
        assert database.executedSql.stream().anyMatch(sql ->
                sql.contains("CREATE TABLE rbvm.risk_method_selection_policy"));
        assert database.executedSql.stream().anyMatch(sql ->
                sql.contains("CREATE TABLE rbvm.risk_method_selection_policy_activation_event"));
        assert database.executedSql.stream().anyMatch(sql ->
                sql.contains("CREATE VIEW rbvm.current_risk_method_selection_policy_activation"));
        assert database.executedSql.stream().anyMatch(sql ->
                sql.contains("CREATE VIEW rbvm.active_risk_method_selection_policy"));
        assert database.executedSql.stream().anyMatch(sql ->
                sql.contains("CREATE TABLE rbvm.active_risk_method_execution_binding"));
        assert database.executedSql.stream().anyMatch(sql ->
                sql.contains("CREATE INDEX exposure_tenant_case_lookup_idx"));
        assert database.executedSql.stream().anyMatch(sql ->
                sql.contains("CREATE TABLE rbvm.finding_mvp_priority_result"));
        assert database.executedSql.stream().anyMatch(sql ->
                sql.contains("CREATE TABLE rbvm.public_intelligence_sync_run"));
        assert database.executedSql.stream().anyMatch(sql ->
                sql.contains("CREATE VIEW rbvm.current_public_intelligence_record"));
        assert database.executedSql.stream().anyMatch(sql ->
                sql.contains("CREATE TABLE rbvm.public_intelligence_sync_job"));
        assert database.executedSql.stream().anyMatch(sql ->
                sql.contains("CREATE VIEW rbvm.public_intelligence_provider_status_v1"));

        long observationCreates = count(database, "CREATE TABLE rbvm.observation (");
        long operationalFindingCreates = count(database, "CREATE VIEW rbvm.operational_finding");
        long applicabilityCreates = count(database, "CREATE TABLE rbvm.applicability_assessment");
        long cvssCreates = count(database, "CREATE TABLE rbvm.cvss_v31_base_evidence");
        long kevSnapshotCreates = count(database, "CREATE TABLE rbvm.cisa_kev_catalog_snapshot");
        long kevEvidenceCreates = count(database, "CREATE TABLE rbvm.cisa_kev_evidence");
        long epssSnapshotCreates = count(database, "CREATE TABLE rbvm.epss_score_snapshot");
        long epssEvidenceCreates = count(database, "CREATE TABLE rbvm.epss_evidence");
        long assetContextSnapshotCreates = count(database, "CREATE TABLE rbvm.asset_context_snapshot");
        long assetContextEvidenceCreates = count(database, "CREATE TABLE rbvm.asset_context_evidence");
        long networkReachabilitySnapshotCreates = count(database, "CREATE TABLE rbvm.network_reachability_snapshot");
        long networkReachabilityEvidenceCreates = count(database, "CREATE TABLE rbvm.network_reachability_evidence");
        long businessImpactSnapshotCreates = count(database, "CREATE TABLE rbvm.business_impact_snapshot");
        long businessImpactEvidenceCreates = count(database, "CREATE TABLE rbvm.business_impact_evidence");
        long methodologyPolicyCreates = count(database, "CREATE TABLE rbvm.decision_methodology_policy");
        long methodologyEvidencePolicyCreates = count(database, "CREATE TABLE rbvm.decision_methodology_evidence_policy");
        long methodologyAllowlistCreates = count(database, "CREATE TABLE rbvm.decision_methodology_source_allowlist");
        long decisionInputSnapshotCreates = count(database, "CREATE TABLE rbvm.decision_input_snapshot");
        long decisionInputDimensionCreates = count(database, "CREATE TABLE rbvm.decision_input_dimension");
        long decisionInputReferenceCreates = count(database, "CREATE TABLE rbvm.decision_input_evidence_reference");
        long managedAssetCreates = count(database, "CREATE TABLE rbvm.managed_asset (");
        long managedAssetRevisionCreates = count(database, "CREATE TABLE rbvm.managed_asset_revision");
        long scannerManagedAssetLinkCreates = count(
                database, "CREATE TABLE rbvm.scanner_managed_asset_link_event");
        long findingReachabilityLinkCreates = count(
                database, "CREATE TABLE rbvm.finding_reachability_scope_link_event");
        long findingBusinessServiceLinkCreates = count(
                database, "CREATE TABLE rbvm.finding_business_service_link_event");
        long v3ContractAlterations = count(database, "RBVM_DECISION_INPUT_SNAPSHOT_V3");
        long formulaResultCreates = count(database, "CREATE TABLE rbvm.formula_result");
        long derivedRiskResultCreates = count(database, "CREATE TABLE rbvm.derived_risk_result");
        long riskMethodSelectionCreates = count(
                database,
                "CREATE TABLE rbvm.risk_method_selection_policy"
        );
        long riskMethodSelectionActivationCreates = count(
                database,
                "CREATE TABLE rbvm.risk_method_selection_policy_activation_event"
        );
        long activeRiskMethodExecutionBindingCreates = count(
                database,
                "CREATE TABLE rbvm.active_risk_method_execution_binding"
        );
        long findingsHotPathIndexCreates = count(
                database,
                "CREATE INDEX exposure_tenant_case_lookup_idx"
        );
        long canonicalMvpPriorityCreates = count(
                database,
                "CREATE TABLE rbvm.finding_mvp_priority_result"
        );
        long publicIntelligenceSyncCreates = count(
                database,
                "CREATE TABLE rbvm.public_intelligence_sync_run"
        );
        long currentPublicIntelligenceCreates = count(
                database,
                "CREATE VIEW rbvm.current_public_intelligence_record"
        );
        long publicIntelligenceJobCreates = count(
                database,
                "CREATE TABLE rbvm.public_intelligence_sync_job"
        );
        long publicIntelligenceProviderStatusCreates = count(
                database,
                "CREATE VIEW rbvm.public_intelligence_provider_status_v1"
        );

        assert migrator.migrate() == LATEST_SCHEMA_VERSION;
        assert database.commits == LATEST_SCHEMA_VERSION : "replay must not reapply migrations";
        assert count(database, "CREATE TABLE rbvm.observation (") == observationCreates;
        assert count(database, "CREATE VIEW rbvm.operational_finding") == operationalFindingCreates;
        assert count(database, "CREATE TABLE rbvm.applicability_assessment") == applicabilityCreates;
        assert count(database, "CREATE TABLE rbvm.cvss_v31_base_evidence") == cvssCreates;
        assert count(database, "CREATE TABLE rbvm.cisa_kev_catalog_snapshot") == kevSnapshotCreates;
        assert count(database, "CREATE TABLE rbvm.cisa_kev_evidence") == kevEvidenceCreates;
        assert count(database, "CREATE TABLE rbvm.epss_score_snapshot") == epssSnapshotCreates;
        assert count(database, "CREATE TABLE rbvm.epss_evidence") == epssEvidenceCreates;
        assert count(database, "CREATE TABLE rbvm.asset_context_snapshot") == assetContextSnapshotCreates;
        assert count(database, "CREATE TABLE rbvm.asset_context_evidence") == assetContextEvidenceCreates;
        assert count(database, "CREATE TABLE rbvm.network_reachability_snapshot") == networkReachabilitySnapshotCreates;
        assert count(database, "CREATE TABLE rbvm.network_reachability_evidence") == networkReachabilityEvidenceCreates;
        assert count(database, "CREATE TABLE rbvm.business_impact_snapshot") == businessImpactSnapshotCreates;
        assert count(database, "CREATE TABLE rbvm.business_impact_evidence") == businessImpactEvidenceCreates;
        assert count(database, "CREATE TABLE rbvm.decision_methodology_policy") == methodologyPolicyCreates;
        assert count(database, "CREATE TABLE rbvm.decision_methodology_evidence_policy") == methodologyEvidencePolicyCreates;
        assert count(database, "CREATE TABLE rbvm.decision_methodology_source_allowlist") == methodologyAllowlistCreates;
        assert count(database, "CREATE TABLE rbvm.decision_input_snapshot") == decisionInputSnapshotCreates;
        assert count(database, "CREATE TABLE rbvm.decision_input_dimension") == decisionInputDimensionCreates;
        assert count(database, "CREATE TABLE rbvm.decision_input_evidence_reference") == decisionInputReferenceCreates;
        assert count(database, "CREATE TABLE rbvm.managed_asset (") == managedAssetCreates;
        assert count(database, "CREATE TABLE rbvm.managed_asset_revision") == managedAssetRevisionCreates;
        assert count(database, "CREATE TABLE rbvm.scanner_managed_asset_link_event")
                == scannerManagedAssetLinkCreates;
        assert count(database, "CREATE TABLE rbvm.finding_reachability_scope_link_event")
                == findingReachabilityLinkCreates;
        assert count(database, "CREATE TABLE rbvm.finding_business_service_link_event")
                == findingBusinessServiceLinkCreates;
        assert count(database, "RBVM_DECISION_INPUT_SNAPSHOT_V3") == v3ContractAlterations;
        assert count(database, "CREATE TABLE rbvm.formula_result") == formulaResultCreates;
        assert count(database, "CREATE TABLE rbvm.derived_risk_result") == derivedRiskResultCreates;
        assert count(database, "CREATE TABLE rbvm.risk_method_selection_policy")
                == riskMethodSelectionCreates;
        assert count(database, "CREATE TABLE rbvm.risk_method_selection_policy_activation_event")
                == riskMethodSelectionActivationCreates;
        assert count(database, "CREATE TABLE rbvm.active_risk_method_execution_binding")
                == activeRiskMethodExecutionBindingCreates;
        assert count(database, "CREATE INDEX exposure_tenant_case_lookup_idx")
                == findingsHotPathIndexCreates;
        assert count(database, "CREATE TABLE rbvm.finding_mvp_priority_result")
                == canonicalMvpPriorityCreates;
        assert count(database, "CREATE TABLE rbvm.public_intelligence_sync_run")
                == publicIntelligenceSyncCreates;
        assert count(database, "CREATE VIEW rbvm.current_public_intelligence_record")
                == currentPublicIntelligenceCreates;
        assert count(database, "CREATE TABLE rbvm.public_intelligence_sync_job")
                == publicIntelligenceJobCreates;
        assert count(database, "CREATE VIEW rbvm.public_intelligence_provider_status_v1")
                == publicIntelligenceProviderStatusCreates;
        assert database.advisoryLocks == 2;
        assert database.advisoryUnlocks == 2;
    }

    private static long count(FakeDatabase database, String marker) {
        return database.executedSql.stream().filter(sql -> sql.contains(marker)).count();
    }

    private static void rejectsChecksumDrift() throws Exception {
        FakeDatabase database = new FakeDatabase();
        PostgresMigrator migrator = new PostgresMigrator(database::connection);
        migrator.migrate();
        database.checksums.put(2, "0".repeat(64));
        boolean rejected = false;
        try {
            migrator.migrate();
        } catch (IOException expected) {
            rejected = expected.getMessage().contains("checksum mismatch");
        }
        assert rejected;
    }

    private static void rollsBackFailedMigration() {
        FakeDatabase database = new FakeDatabase();
        database.failWhenSqlContains = "CREATE TABLE rbvm.asset (";
        PostgresMigrator migrator = new PostgresMigrator(database::connection);
        boolean failed = false;
        try {
            migrator.migrate();
        } catch (IOException expected) {
            failed = expected.getMessage().contains("migration failed");
        }
        assert failed;
        assert database.rollbacks == 1;
        assert database.commits == 0;
        assert database.checksums.isEmpty();
    }

    private static final class FakeDatabase {
        private final Map<Integer, String> checksums = new HashMap<>();
        private final List<String> executedSql = new ArrayList<>();
        private int commits;
        private int rollbacks;
        private int advisoryLocks;
        private int advisoryUnlocks;
        private String failWhenSqlContains;

        private Connection connection() {
            return proxy(Connection.class, this::connectionCall);
        }

        private Object connectionCall(Object proxy, Method method, Object[] arguments)
                throws SQLException {
            return switch (method.getName()) {
                case "getMetaData" -> metadata();
                case "prepareStatement" -> prepared((String) arguments[0]);
                case "createStatement" -> statement();
                case "commit" -> { commits++; yield null; }
                case "rollback" -> { rollbacks++; yield null; }
                case "setAutoCommit", "close" -> null;
                case "getAutoCommit" -> true;
                case "isClosed" -> false;
                case "unwrap" -> null;
                case "isWrapperFor" -> false;
                default -> defaultValue(method.getReturnType());
            };
        }

        private DatabaseMetaData metadata() {
            return proxy(DatabaseMetaData.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "getDatabaseProductName" -> "PostgreSQL";
                case "getDatabaseMajorVersion" -> 18;
                default -> defaultValue(method.getReturnType());
            });
        }

        private Statement statement() {
            return proxy(Statement.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "execute" -> {
                    String sql = (String) arguments[0];
                    if (failWhenSqlContains != null && sql.contains(failWhenSqlContains)) {
                        throw new SQLException("synthetic migration failure");
                    }
                    executedSql.add(sql);
                    yield false;
                }
                case "executeQuery" -> resultSet(
                        checksums.isEmpty()
                                ? List.of(0)
                                : List.of(checksums.keySet().stream().mapToInt(Integer::intValue)
                                        .max().orElse(0))
                );
                case "close" -> null;
                default -> defaultValue(method.getReturnType());
            });
        }

        private PreparedStatement prepared(String sql) {
            Map<Integer, Object> parameters = new HashMap<>();
            return proxy(PreparedStatement.class, (proxy, method, arguments) -> {
                String name = method.getName();
                if (name.startsWith("set") && arguments != null && arguments.length >= 2
                        && arguments[0] instanceof Integer index) {
                    parameters.put(index, arguments[1]);
                    return null;
                }
                return switch (name) {
                    case "execute" -> {
                        String normalized = sql.toLowerCase(Locale.ROOT);
                        if (normalized.contains("pg_advisory_lock")) advisoryLocks++;
                        else if (normalized.contains("pg_advisory_unlock")) advisoryUnlocks++;
                        yield false;
                    }
                    case "executeQuery" -> {
                        if (sql.contains("SELECT sha256")) {
                            String checksum = checksums.get((Integer) parameters.get(1));
                            yield resultSet(checksum == null ? List.of() : List.of(checksum));
                        }
                        yield resultSet(List.of());
                    }
                    case "executeUpdate" -> {
                        if (sql.contains("INSERT INTO rbvm.schema_migration")) {
                            checksums.put((Integer) parameters.get(1), (String) parameters.get(3));
                        }
                        yield 1;
                    }
                    case "close" -> null;
                    default -> defaultValue(method.getReturnType());
                };
            });
        }

        private static ResultSet resultSet(List<?> values) {
            int[] cursor = {-1};
            return proxy(ResultSet.class, (proxy, method, arguments) -> switch (method.getName()) {
                case "next" -> ++cursor[0] < values.size();
                case "getString" -> values.get(cursor[0]).toString();
                case "getInt" -> ((Number) values.get(cursor[0])).intValue();
                case "getLong" -> ((Number) values.get(cursor[0])).longValue();
                case "close" -> null;
                default -> defaultValue(method.getReturnType());
            });
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler);
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0F;
        if (type == double.class) return 0D;
        if (type == char.class) return '\0';
        return null;
    }
}
