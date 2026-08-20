package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmResolvedDecisionInput;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.AssetContextEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.BusinessMissionImpactEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ExploitationProbabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.KnownExploitationEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.NetworkReachabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.TechnicalSeverityEvidenceValue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class PostgresDecisionInputEvidenceResolverSelfTest {
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID FINDING_ID = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-20T05:00:00Z");
    private static final String POLICY_SHA = "a".repeat(64);

    private PostgresDecisionInputEvidenceResolverSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        resolvesExactNativeRowsUnderOneRepeatableReadSnapshot();
        rejectsMissingOrMutatedNativeProvenance();
        skipsMissingDimensionsAndRejectsOldSchema();
        System.out.println("PostgresDecisionInputEvidenceResolverSelfTest: PASS");
    }

    private static void resolvesExactNativeRowsUnderOneRepeatableReadSnapshot() throws Exception {
        Fixture fixture = fixture(false);
        FakeDatabase database = populatedDatabase(fixture);
        PostgresDecisionInputEvidenceResolver resolver =
                new PostgresDecisionInputEvidenceResolver(database::connection, 17);

        RbvmResolvedDecisionInput resolved = resolver.resolve(fixture.snapshot());

        assert resolved.snapshot().snapshotSha256().equals(fixture.snapshot().snapshotSha256());
        assert ((ApplicabilityEvidenceValue) resolved.evidence(EvidenceDimension.APPLICABILITY).get(0))
                .status().name().equals("APPLICABLE");
        assert ((TechnicalSeverityEvidenceValue) resolved.evidence(EvidenceDimension.TECHNICAL_SEVERITY).get(0))
                .baseScore().compareTo(new BigDecimal("9.8")) == 0;
        assert ((KnownExploitationEvidenceValue) resolved.evidence(EvidenceDimension.KNOWN_EXPLOITATION).get(0))
                .status().name().equals("LISTED");
        assert ((ExploitationProbabilityEvidenceValue) resolved.evidence(EvidenceDimension.EXPLOITATION_PROBABILITY).get(0))
                .probability().compareTo(new BigDecimal("0.42")) == 0;
        assert ((AssetContextEvidenceValue) resolved.evidence(EvidenceDimension.ASSET_CONTEXT).get(0))
                .businessService().equals("Payments");
        assert ((NetworkReachabilityEvidenceValue) resolved.evidence(EvidenceDimension.NETWORK_REACHABILITY).get(0))
                .targetPort() == 443;
        assert ((BusinessMissionImpactEvidenceValue) resolved.evidence(EvidenceDimension.BUSINESS_MISSION_IMPACT).get(0))
                .businessServiceNormalized().equals("payments");

        assert database.connectionsOpened == 1;
        assert database.readOnlyTransactions == 1;
        assert database.repeatableReadTransactions == 1;
        assert database.autoCommitDisabled == 1;
        assert database.commits == 1;
        assert database.rollbacks == 0;
        assert database.nativeEvidenceQueries == EvidenceDimension.values().length;
        assert database.queries.stream().noneMatch(sql -> sql.contains("current_"));
        assert database.queries.stream().noneMatch(sql -> sql.contains("finding_"));
        assert database.queries.stream().filter(FakeDatabase::isNativeEvidenceQuery)
                .allMatch(sql -> sql.contains("id = ?"));
        assert database.requestedEvidenceIds.equals(fixture.referencesByDimension().values().stream()
                .map(EvidenceReference::evidenceId)
                .toList());
    }

    private static void rejectsMissingOrMutatedNativeProvenance() throws Exception {
        Fixture fixture = fixture(false);
        FakeDatabase missing = populatedDatabase(fixture);
        missing.rows.get(EvidenceDimension.TECHNICAL_SEVERITY).clear();
        PostgresDecisionInputEvidenceResolver missingResolver =
                new PostgresDecisionInputEvidenceResolver(missing::connection, 17);

        boolean missingRejected = false;
        try {
            missingResolver.resolve(fixture.snapshot());
        } catch (java.io.IOException expected) {
            missingRejected = expected.getMessage().contains("does not resolve to native immutable evidence");
        }
        assert missingRejected;
        assert missing.commits == 0;
        assert missing.rollbacks == 1;

        FakeDatabase mutated = populatedDatabase(fixture);
        EvidenceReference cvss = fixture.referencesByDimension().get(EvidenceDimension.TECHNICAL_SEVERITY);
        mutated.rows.get(EvidenceDimension.TECHNICAL_SEVERITY).put(
                cvss.evidenceId(),
                row("f".repeat(64), cvss.evidenceSource(), cvss.observedAt(),
                        "3.1", new BigDecimal("9.8"),
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        );
        PostgresDecisionInputEvidenceResolver mutatedResolver =
                new PostgresDecisionInputEvidenceResolver(mutated::connection, 17);

        boolean provenanceRejected = false;
        try {
            mutatedResolver.resolve(fixture.snapshot());
        } catch (java.io.IOException expected) {
            provenanceRejected = expected.getMessage().contains("provenance does not match snapshot reference");
        }
        assert provenanceRejected;
        assert mutated.commits == 0;
        assert mutated.rollbacks == 1;
    }

    private static void skipsMissingDimensionsAndRejectsOldSchema() throws Exception {
        Fixture fixture = fixture(true);
        FakeDatabase database = populatedDatabase(fixture);
        PostgresDecisionInputEvidenceResolver resolver =
                new PostgresDecisionInputEvidenceResolver(database::connection, 17);
        RbvmResolvedDecisionInput resolved = resolver.resolve(fixture.snapshot());

        assert resolved.evidence(EvidenceDimension.KNOWN_EXPLOITATION).isEmpty();
        assert database.nativeEvidenceQueries == EvidenceDimension.values().length - 1;
        assert database.queries.stream().noneMatch(sql -> sql.contains("from rbvm.cisa_kev_evidence"));

        boolean schemaRejected = false;
        try {
            new PostgresDecisionInputEvidenceResolver(database::connection, 16);
        } catch (java.io.IOException expected) {
            schemaRejected = expected.getMessage().contains("older than required version 17");
        }
        assert schemaRejected;
    }

    private static Fixture fixture(boolean missingKev) {
        EnumMap<EvidenceDimension, DimensionInput> dimensions = new EnumMap<>(EvidenceDimension.class);
        EnumMap<EvidenceDimension, EvidenceReference> references = new EnumMap<>(EvidenceDimension.class);

        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            if (missingKev && dimension == EvidenceDimension.KNOWN_EXPLOITATION) {
                dimensions.put(dimension, new DimensionInput(dimension, DimensionState.MISSING, List.of()));
                continue;
            }
            EvidenceReference reference = reference(dimension, source(dimension), dimension.ordinal() + 1);
            references.put(dimension, reference);
            dimensions.put(dimension, new DimensionInput(dimension, DimensionState.PRESENT, List.of(reference)));
        }
        return new Fixture(
                RbvmDecisionInputSnapshot.create(
                        FINDING_ID,
                        1,
                        POLICY_SHA,
                        EVALUATED_AT,
                        dimensions
                ),
                references
        );
    }

    private static FakeDatabase populatedDatabase(Fixture fixture) {
        FakeDatabase database = new FakeDatabase();
        for (Map.Entry<EvidenceDimension, EvidenceReference> entry
                : fixture.referencesByDimension().entrySet()) {
            EvidenceReference reference = entry.getValue();
            Object[] row = switch (entry.getKey()) {
                case APPLICABILITY -> row(
                        reference.evidenceSha256(), reference.evidenceSource(), reference.observedAt(),
                        "APPLICABLE", "package is deployed");
                case TECHNICAL_SEVERITY -> row(
                        reference.evidenceSha256(), reference.evidenceSource(), reference.observedAt(),
                        "3.1", new BigDecimal("9.8"),
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
                case KNOWN_EXPLOITATION -> row(
                        reference.evidenceSha256(), reference.evidenceSource(), reference.observedAt(),
                        "LISTED", LocalDate.parse("2026-08-01"), LocalDate.parse("2026-08-22"), "KNOWN");
                case EXPLOITATION_PROBABILITY -> row(
                        reference.evidenceSha256(), reference.evidenceSource(), reference.observedAt(),
                        new BigDecimal("0.42"), new BigDecimal("0.93"),
                        "2026.08.20", LocalDate.parse("2026-08-20"));
                case ASSET_CONTEXT -> row(
                        reference.evidenceSha256(), reference.evidenceSource(), reference.observedAt(),
                        "PRODUCTION", "Payments", "payments-owner", "MISSION_CRITICAL");
                case NETWORK_REACHABILITY -> row(
                        reference.evidenceSha256(), reference.evidenceSource(), reference.observedAt(),
                        "INTERNET", "external edge", "TCP", 443, "https", "REACHABLE", "ACTIVE_PROBE");
                case BUSINESS_MISSION_IMPACT -> row(
                        reference.evidenceSha256(), reference.evidenceSource(), reference.observedAt(),
                        "Payments", "payments", "AVAILABILITY", "SEVERE",
                        "BUSINESS_IMPACT_ANALYSIS", "payment outage stops settlement");
            };
            database.rows.get(entry.getKey()).put(reference.evidenceId(), row);
        }
        return database;
    }

    private static EvidenceReference reference(
            EvidenceDimension dimension,
            String source,
            int seed
    ) {
        return new EvidenceReference(
                dimension,
                UUID.nameUUIDFromBytes(("resolver-" + seed).getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                Integer.toHexString(seed).substring(0, 1).repeat(64),
                source,
                EVALUATED_AT.minusSeconds(seed * 60L)
        );
    }

    private static String source(EvidenceDimension dimension) {
        return switch (dimension) {
            case APPLICABILITY -> "app-source";
            case TECHNICAL_SEVERITY -> "cvss-source";
            case KNOWN_EXPLOITATION -> "kev-source";
            case EXPLOITATION_PROBABILITY -> "epss-source";
            case ASSET_CONTEXT -> "cmdb";
            case NETWORK_REACHABILITY -> "probe";
            case BUSINESS_MISSION_IMPACT -> "bia";
        };
    }

    private record Fixture(
            RbvmDecisionInputSnapshot snapshot,
            EnumMap<EvidenceDimension, EvidenceReference> referencesByDimension
    ) {
    }

    private static Object[] row(Object... values) {
        return values;
    }

    private static final class FakeDatabase {
        private final EnumMap<EvidenceDimension, Map<UUID, Object[]>> rows =
                new EnumMap<>(EvidenceDimension.class);
        private final List<String> queries = new ArrayList<>();
        private final List<UUID> requestedEvidenceIds = new ArrayList<>();
        private int connectionsOpened;
        private int readOnlyTransactions;
        private int repeatableReadTransactions;
        private int autoCommitDisabled;
        private int nativeEvidenceQueries;
        private int commits;
        private int rollbacks;

        private FakeDatabase() {
            for (EvidenceDimension dimension : EvidenceDimension.values()) {
                rows.put(dimension, new HashMap<>());
            }
        }

        private Connection connection() {
            connectionsOpened++;
            return proxy(Connection.class, (proxy, method, args) -> switch (method.getName()) {
                case "prepareStatement" -> prepared((String) args[0]);
                case "setReadOnly" -> {
                    if (Boolean.TRUE.equals(args[0])) readOnlyTransactions++;
                    yield null;
                }
                case "setTransactionIsolation" -> {
                    if ((Integer) args[0] == Connection.TRANSACTION_REPEATABLE_READ) {
                        repeatableReadTransactions++;
                    }
                    yield null;
                }
                case "setAutoCommit" -> {
                    if (Boolean.FALSE.equals(args[0])) autoCommitDisabled++;
                    yield null;
                }
                case "commit" -> { commits++; yield null; }
                case "rollback" -> { rollbacks++; yield null; }
                case "close" -> null;
                case "isClosed" -> false;
                default -> defaultValue(method.getReturnType());
            });
        }

        private PreparedStatement prepared(String sql) {
            String normalized = String.join(" ", sql.split("\\s+"))
                    .toLowerCase(java.util.Locale.ROOT);
            queries.add(normalized);
            Map<Integer, Object> parameters = new HashMap<>();
            return proxy(PreparedStatement.class, (proxy, method, args) -> {
                String name = method.getName();
                if (name.startsWith("set") && args != null && args.length >= 2
                        && args[0] instanceof Integer index) {
                    parameters.put(index, args[1]);
                    return null;
                }
                return switch (name) {
                    case "executeQuery" -> query(normalized, parameters);
                    case "close" -> null;
                    default -> defaultValue(method.getReturnType());
                };
            });
        }

        private ResultSet query(String sql, Map<Integer, Object> parameters) {
            if (sql.contains("from rbvm.tenant")) {
                return resultRows(row(TENANT_ID));
            }
            EvidenceDimension dimension = dimensionFor(sql);
            nativeEvidenceQueries++;
            if (!sql.contains("id = ?")) {
                throw new AssertionError("native resolution must use exact evidence UUID: " + sql);
            }
            UUID evidenceId = (UUID) parameters.get(2);
            requestedEvidenceIds.add(evidenceId);
            Object[] value = rows.get(dimension).get(evidenceId);
            return value == null ? resultRows() : resultRows(value);
        }

        private static EvidenceDimension dimensionFor(String sql) {
            if (sql.contains("from rbvm.applicability_assessment")) {
                return EvidenceDimension.APPLICABILITY;
            }
            if (sql.contains("from rbvm.cvss_v31_base_evidence")) {
                return EvidenceDimension.TECHNICAL_SEVERITY;
            }
            if (sql.contains("from rbvm.cisa_kev_evidence")) {
                return EvidenceDimension.KNOWN_EXPLOITATION;
            }
            if (sql.contains("from rbvm.epss_evidence")) {
                return EvidenceDimension.EXPLOITATION_PROBABILITY;
            }
            if (sql.contains("from rbvm.asset_context_evidence")) {
                return EvidenceDimension.ASSET_CONTEXT;
            }
            if (sql.contains("from rbvm.network_reachability_evidence")) {
                return EvidenceDimension.NETWORK_REACHABILITY;
            }
            if (sql.contains("from rbvm.business_impact_evidence")) {
                return EvidenceDimension.BUSINESS_MISSION_IMPACT;
            }
            throw new AssertionError("Unexpected query:\n" + sql);
        }

        private static boolean isNativeEvidenceQuery(String sql) {
            try {
                dimensionFor(sql);
                return true;
            } catch (AssertionError ignored) {
                return false;
            }
        }
    }

    private static ResultSet resultRows(Object[]... values) {
        int[] cursor = {-1};
        return proxy(ResultSet.class, (proxy, method, args) -> switch (method.getName()) {
            case "next" -> ++cursor[0] < values.length;
            case "getObject" -> {
                Object value = values[cursor[0]][(Integer) args[0] - 1];
                if (args.length == 2 && args[1] instanceof Class<?> type && value != null) {
                    yield type.cast(value);
                }
                yield value;
            }
            case "getString" -> {
                Object value = values[cursor[0]][(Integer) args[0] - 1];
                yield value == null ? null : value.toString();
            }
            case "getBigDecimal" -> (BigDecimal) values[cursor[0]][(Integer) args[0] - 1];
            case "getTimestamp" -> {
                Object value = values[cursor[0]][(Integer) args[0] - 1];
                yield value instanceof Timestamp timestamp
                        ? timestamp
                        : Timestamp.from((Instant) value);
            }
            case "close" -> null;
            default -> defaultValue(method.getReturnType());
        });
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
