package io.rbvm.postgres;

import io.rbvm.domain.CaseActionCommand;
import io.rbvm.domain.CaseAuditEvent;
import io.rbvm.domain.CasePage;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.CatalogSnapshot;
import io.rbvm.domain.DomainCatalog;
import io.rbvm.domain.DomainMaterializationResult;
import io.rbvm.domain.PreparedCaseAction;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public final class PostgresApplicabilityAwareCatalogSelfTest {
    private static final UUID TENANT = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID FINDING = UUID.fromString("20000000-0000-5000-8000-000000000001");
    private static final String EXPOSURE_PUBLIC_ID = "a".repeat(64);

    private PostgresApplicabilityAwareCatalogSelfTest() {
    }

    public static void main(String[] args) {
        addsFindingUuidAndApplicabilityWithoutDroppingNullableFields();
        System.out.println("PostgresApplicabilityAwareCatalogSelfTest: PASS");
    }

    private static void addsFindingUuidAndApplicabilityWithoutDroppingNullableFields() {
        PostgresApplicabilityAwareCatalog catalog = new PostgresApplicabilityAwareCatalog(
                new StubCatalog(),
                PostgresApplicabilityAwareCatalogSelfTest::connection
        );
        Map<String, Object> detail = catalog.caseDetail("case-a").orElseThrow();
        @SuppressWarnings("unchecked")
        Map<String, Object> exposure = ((List<Map<String, Object>>) detail.get("exposures")).get(0);
        assert exposure.get("findingId").equals(FINDING.toString());
        assert exposure.get("applicabilityStatus").equals("UNKNOWN");
        assert exposure.get("applicabilityAssessed").equals(false);
        assert exposure.containsKey("applicabilityReason");
        assert exposure.get("applicabilityReason") == null;
        assert exposure.containsKey("resolvedAt");
        assert exposure.get("resolvedAt") == null;
        assert exposure.get("applicabilityEvaluatedAt") == null;
    }

    private static Connection connection() {
        return proxy(Connection.class, (proxy, method, arguments) -> switch (method.getName()) {
            case "prepareStatement" -> prepared((String) arguments[0]);
            case "close" -> null;
            case "isClosed" -> false;
            default -> defaultValue(method.getReturnType());
        });
    }

    private static PreparedStatement prepared(String sql) {
        Map<Integer, Object> parameters = new LinkedHashMap<>();
        return proxy(PreparedStatement.class, (proxy, method, arguments) -> {
            String name = method.getName();
            if (name.startsWith("set") && arguments != null && arguments.length >= 2
                    && arguments[0] instanceof Integer index) {
                parameters.put(index, arguments[1]);
                return null;
            }
            return switch (name) {
                case "executeQuery" -> {
                    if (sql.contains("SELECT id FROM rbvm.tenant")) {
                        assert "local".equals(parameters.get(1));
                        yield rows(Map.of("id", TENANT));
                    }
                    if (sql.contains("FROM rbvm.finding_applicability")) {
                        assert TENANT.equals(parameters.get(1));
                        assert EXPOSURE_PUBLIC_ID.equals(parameters.get(2));
                        Map<String, Object> row = new LinkedHashMap<>();
                        row.put("finding_id", FINDING);
                        row.put("applicability_status", "UNKNOWN");
                        row.put("applicability_assessed", false);
                        row.put("applicability_reason", null);
                        row.put("applicability_evidence_source", null);
                        row.put("applicability_evaluated_at", null);
                        yield rows(row);
                    }
                    throw new AssertionError("Unexpected query: " + sql);
                }
                case "close" -> null;
                default -> defaultValue(method.getReturnType());
            };
        });
    }

    @SafeVarargs
    private static ResultSet rows(Map<String, Object>... values) {
        int[] cursor = {-1};
        return proxy(ResultSet.class, (proxy, method, arguments) -> switch (method.getName()) {
            case "next" -> ++cursor[0] < values.length;
            case "getObject" -> {
                Object key = arguments[0];
                if (key instanceof Integer) yield values[cursor[0]].values().iterator().next();
                yield values[cursor[0]].get(key.toString());
            }
            case "getString" -> {
                Object value = values[cursor[0]].get(arguments[0].toString());
                yield value == null ? null : value.toString();
            }
            case "getBoolean" -> Boolean.TRUE.equals(values[cursor[0]].get(arguments[0].toString()));
            case "getTimestamp" -> (Timestamp) values[cursor[0]].get(arguments[0].toString());
            case "close" -> null;
            default -> defaultValue(method.getReturnType());
        });
    }

    private static final class StubCatalog implements DomainCatalog {
        @Override
        public String backend() {
            return "POSTGRESQL";
        }

        @Override
        public DomainMaterializationResult materialize(
                UUID importId, Path csvPath, String sourceProfileId, String contractId) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CatalogSnapshot snapshot() {
            throw new UnsupportedOperationException();
        }

        @Override
        public CasePage queryCases(CaseQuery query) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<Map<String, Object>> caseDetail(String caseId) {
            Map<String, Object> exposure = new LinkedHashMap<>();
            exposure.put("exposureId", EXPOSURE_PUBLIC_ID);
            exposure.put("product", "pyarrow");
            exposure.put("resolvedAt", null);
            Map<String, Object> detail = new LinkedHashMap<>();
            detail.put("caseId", caseId);
            detail.put("exposures", List.of(exposure));
            return Optional.of(detail);
        }

        @Override
        public PreparedCaseAction prepareCaseAction(
                long sequence, String caseId, CaseActionCommand command,
                String idempotencyKey, String actorId, String actorAssurance, Instant occurredAt) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Map<String, Object> applyCaseEvent(CaseAuditEvent event) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isMaterialized(UUID importId) {
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler);
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == double.class) return 0D;
        if (type == float.class) return 0F;
        if (type == short.class) return (short) 0;
        if (type == byte.class) return (byte) 0;
        if (type == char.class) return '\0';
        return null;
    }
}
