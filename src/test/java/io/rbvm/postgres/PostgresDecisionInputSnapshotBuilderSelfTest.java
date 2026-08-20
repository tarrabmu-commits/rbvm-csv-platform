package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.AmbiguityHandling;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.FreshnessMode;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.LegacyPriorityHandling;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.MissingEvidenceHandling;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.SourceSelectionMode;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.SubjectScope;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
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
import java.util.Optional;
import java.util.UUID;

public final class PostgresDecisionInputSnapshotBuilderSelfTest {
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID FINDING_ID = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID ASSET_ID = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID VULNERABILITY_ID = UUID.fromString("33333333-3333-4333-8333-333333333333");
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-19T18:00:00Z");

    private PostgresDecisionInputSnapshotBuilderSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        buildsFromNativeHistoryUnderOneRepeatableReadSnapshot();
        requiresExactRegisteredMethodologyRevisionAndSha();
        rejectsUnknownFindingAndOldSchema();
        System.out.println("PostgresDecisionInputSnapshotBuilderSelfTest: PASS");
    }

    private static void buildsFromNativeHistoryUnderOneRepeatableReadSnapshot() throws Exception {
        RbvmDecisionMethodologyPolicy methodology = methodology(7);
        FakeDatabase database = populatedDatabase();
        PostgresDecisionInputSnapshotBuilder builder = new PostgresDecisionInputSnapshotBuilder(
                database::connection,
                policyStore(methodology),
                17
        );

        RbvmDecisionInputSnapshot snapshot = builder.build(
                FINDING_ID,
                methodology.revision(),
                methodology.policySha256(),
                EVALUATED_AT
        );

        assert snapshot.findingId().equals(FINDING_ID);
        assert snapshot.methodologyRevision() == methodology.revision();
        assert snapshot.methodologyPolicySha256().equals(methodology.policySha256());
        assert snapshot.evaluatedAt().equals(EVALUATED_AT);
        assert snapshot.dimensions().size() == EvidenceDimension.values().length;

        assert dimension(snapshot, EvidenceDimension.APPLICABILITY).state() == DimensionState.PRESENT;

        DimensionInput cvss = dimension(snapshot, EvidenceDimension.TECHNICAL_SEVERITY);
        assert cvss.state() == DimensionState.AMBIGUOUS;
        assert cvss.evidenceReferences().size() == 2;
        assert cvss.evidenceReferences().stream().noneMatch(reference ->
                reference.evidenceId().equals(database.cvssOld));

        assert dimension(snapshot, EvidenceDimension.KNOWN_EXPLOITATION).state()
                == DimensionState.MISSING;

        DimensionInput epss = dimension(snapshot, EvidenceDimension.EXPLOITATION_PROBABILITY);
        assert epss.state() == DimensionState.PRESENT;
        assert epss.evidenceReferences().size() == 1;
        assert epss.evidenceReferences().get(0).evidenceId().equals(database.epssNewerScoreDate);
        assert !epss.evidenceReferences().get(0).evidenceId().equals(database.epssOlderReplay);

        assert dimension(snapshot, EvidenceDimension.ASSET_CONTEXT).state() == DimensionState.PRESENT;

        DimensionInput reachability = dimension(snapshot, EvidenceDimension.NETWORK_REACHABILITY);
        assert reachability.state() == DimensionState.AMBIGUOUS;
        assert reachability.evidenceReferences().size() == 3;

        DimensionInput impact = dimension(snapshot, EvidenceDimension.BUSINESS_MISSION_IMPACT);
        assert impact.state() == DimensionState.PRESENT;
        assert impact.evidenceReferences().size() == 2;

        assert database.readOnlyTransactions == 1;
        assert database.repeatableReadTransactions == 1;
        assert database.autoCommitDisabled == 1;
        assert database.commits == 1;
        assert database.rollbacks == 0;
        assert database.nativeHistoryQueries == 7;
        assert database.queries.stream().noneMatch(sql -> sql.contains("current_"));
        assert database.queries.stream().noneMatch(sql -> sql.contains("finding_cvss"));
        assert database.queries.stream().noneMatch(sql -> sql.contains("finding_epss"));
        assert database.queries.stream().filter(FakeDatabase::isNativeEvidenceQuery)
                .allMatch(sql -> sql.contains("<= ?"));
    }

    private static void requiresExactRegisteredMethodologyRevisionAndSha() throws Exception {
        RbvmDecisionMethodologyPolicy methodology = methodology(8);
        FakeDatabase database = populatedDatabase();
        PostgresDecisionInputSnapshotBuilder builder = new PostgresDecisionInputSnapshotBuilder(
                database::connection,
                policyStore(methodology),
                17
        );

        boolean shaRejected = false;
        try {
            builder.build(FINDING_ID, 8, "f".repeat(64), EVALUATED_AT);
        } catch (java.io.IOException expected) {
            shaRejected = expected.getMessage().contains("revision/SHA");
        }
        assert shaRejected;
        assert database.connectionsOpened == 0 : "policy mismatch must fail before evidence read";

        boolean revisionRejected = false;
        try {
            builder.build(FINDING_ID, 9, methodology.policySha256(), EVALUATED_AT);
        } catch (java.io.IOException expected) {
            revisionRejected = expected.getMessage().contains("revision is not registered");
        }
        assert revisionRejected;
        assert database.connectionsOpened == 0;
    }

    private static void rejectsUnknownFindingAndOldSchema() throws Exception {
        RbvmDecisionMethodologyPolicy methodology = methodology(10);
        FakeDatabase missingFinding = new FakeDatabase(false);
        PostgresDecisionInputSnapshotBuilder builder = new PostgresDecisionInputSnapshotBuilder(
                missingFinding::connection,
                policyStore(methodology),
                17
        );

        boolean findingRejected = false;
        try {
            builder.build(
                    FINDING_ID,
                    methodology.revision(),
                    methodology.policySha256(),
                    EVALUATED_AT
            );
        } catch (java.io.IOException expected) {
            findingRejected = expected.getMessage().contains("Finding_ID");
        }
        assert findingRejected;
        assert missingFinding.rollbacks == 1;
        assert missingFinding.nativeHistoryQueries == 0;

        boolean schemaRejected = false;
        try {
            new PostgresDecisionInputSnapshotBuilder(
                    missingFinding::connection,
                    policyStore(methodology),
                    16
            );
        } catch (java.io.IOException expected) {
            schemaRejected = expected.getMessage().contains("older than required version 17");
        }
        assert schemaRejected;
    }

    private static DimensionInput dimension(
            RbvmDecisionInputSnapshot snapshot,
            EvidenceDimension dimension
    ) {
        return snapshot.dimensions().get(dimension);
    }

    private static RbvmDecisionMethodologyPolicy methodology(int revision) {
        EnumMap<EvidenceDimension, EvidenceSelectionPolicy> policies =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            policies.put(
                    dimension,
                    new EvidenceSelectionPolicy(
                            dimension,
                            SourceSelectionMode.ALL_SOURCES,
                            List.of(),
                            FreshnessMode.NO_AGE_LIMIT,
                            null
                    )
            );
        }
        return RbvmDecisionMethodologyPolicy.create(
                revision,
                SubjectScope.FINDING,
                MissingEvidenceHandling.PRESERVE_UNKNOWN,
                AmbiguityHandling.PRESERVE_AMBIGUOUS,
                LegacyPriorityHandling.EXCLUDE_LEGACY_PRIORITY_TIER,
                policies
        );
    }

    private static DecisionMethodologyPolicyStore policyStore(
            RbvmDecisionMethodologyPolicy methodology
    ) {
        return new DecisionMethodologyPolicyStore() {
            @Override
            public DecisionMethodologyPolicyInstallResult install(
                    RbvmDecisionMethodologyPolicy policy
            ) {
                throw new UnsupportedOperationException("test policy store is read-only");
            }

            @Override
            public Optional<RbvmDecisionMethodologyPolicy> findByRevision(int revision) {
                return revision == methodology.revision()
                        ? Optional.of(methodology)
                        : Optional.empty();
            }
        };
    }

    private static FakeDatabase populatedDatabase() {
        FakeDatabase database = new FakeDatabase(true);
        database.applicability.add(row(
                database.id("applicability"), sha(1), "app-source", time(-300)));

        database.cvssOld = database.id("cvss-old");
        database.cvss.add(row(database.cvssOld, sha(2), "cvss-a", time(-7200)));
        database.cvss.add(row(database.id("cvss-a-latest"), sha(3), "cvss-a", time(-600)));
        database.cvss.add(row(database.id("cvss-b-latest"), sha(4), "cvss-b", time(-300)));

        database.epssNewerScoreDate = database.id("epss-newer-score-date");
        database.epssOlderReplay = database.id("epss-older-replay");
        database.epss.add(row(
                database.epssNewerScoreDate,
                sha(5),
                "first-epss",
                LocalDate.parse("2026-08-19"),
                time(-7200)
        ));
        database.epss.add(row(
                database.epssOlderReplay,
                sha(6),
                "first-epss",
                LocalDate.parse("2026-08-18"),
                time(-60)
        ));

        database.assetContext.add(row(
                database.id("asset-context"), sha(7), "cmdb", time(-120)));

        database.reachability.add(row(
                database.id("reach-443-a"), sha(8), "probe-a", time(-180),
                "INTERNET", " External Edge ", "TCP", 443));
        database.reachability.add(row(
                database.id("reach-443-b"), sha(9), "probe-b", time(-90),
                "INTERNET", "external edge", "TCP", 443));
        database.reachability.add(row(
                database.id("reach-22"), sha(10), "probe-a", time(-60),
                "INTERNET", "external edge", "TCP", 22));

        database.businessImpact.add(row(
                database.id("impact-availability"), sha(11), "bia", time(-300),
                "payments", "AVAILABILITY"));
        database.businessImpact.add(row(
                database.id("impact-integrity"), sha(12), "bia", time(-300),
                "payments", "INTEGRITY"));
        return database;
    }

    private static Instant time(long secondsFromEvaluation) {
        return EVALUATED_AT.plusSeconds(secondsFromEvaluation);
    }

    private static String sha(int seed) {
        return Integer.toHexString(seed).substring(0, 1).repeat(64);
    }

    private static Object[] row(Object... values) {
        return values;
    }

    private static final class FakeDatabase {
        private final boolean findingExists;
        private final List<Object[]> applicability = new ArrayList<>();
        private final List<Object[]> cvss = new ArrayList<>();
        private final List<Object[]> kev = new ArrayList<>();
        private final List<Object[]> epss = new ArrayList<>();
        private final List<Object[]> assetContext = new ArrayList<>();
        private final List<Object[]> reachability = new ArrayList<>();
        private final List<Object[]> businessImpact = new ArrayList<>();
        private final List<String> queries = new ArrayList<>();
        private int connectionsOpened;
        private int readOnlyTransactions;
        private int repeatableReadTransactions;
        private int autoCommitDisabled;
        private int nativeHistoryQueries;
        private int commits;
        private int rollbacks;
        private UUID cvssOld;
        private UUID epssNewerScoreDate;
        private UUID epssOlderReplay;

        private FakeDatabase(boolean findingExists) {
            this.findingExists = findingExists;
        }

        private UUID id(String seed) {
            return UUID.nameUUIDFromBytes(seed.getBytes(java.nio.charset.StandardCharsets.UTF_8));
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
            String normalized = " ".join(sql.split("\\s+")).toLowerCase(java.util.Locale.ROOT);
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
                return rows(row(TENANT_ID));
            }
            if (sql.contains("from rbvm.exposure")) {
                return findingExists ? rows(row(ASSET_ID, VULNERABILITY_ID)) : rows();
            }
            if (isNativeEvidenceQuery(sql)) {
                nativeHistoryQueries++;
                if (!sql.contains("<= ?")) {
                    throw new AssertionError("native evidence query is not bounded as-of evaluatedAt: " + sql);
                }
                if (parameters.get(3) == null) {
                    throw new AssertionError("native evidence query did not bind evaluatedAt");
                }
            }
            if (sql.contains("from rbvm.applicability_assessment")) return rows(applicability);
            if (sql.contains("from rbvm.cvss_v31_base_evidence")) return rows(cvss);
            if (sql.contains("from rbvm.cisa_kev_evidence")) return rows(kev);
            if (sql.contains("from rbvm.epss_evidence")) return rows(epss);
            if (sql.contains("from rbvm.asset_context_evidence")) return rows(assetContext);
            if (sql.contains("from rbvm.network_reachability_evidence")) return rows(reachability);
            if (sql.contains("from rbvm.business_impact_evidence")) return rows(businessImpact);
            throw new AssertionError("Unexpected query:\n" + sql);
        }

        private static boolean isNativeEvidenceQuery(String sql) {
            return sql.contains("from rbvm.applicability_assessment")
                    || sql.contains("from rbvm.cvss_v31_base_evidence")
                    || sql.contains("from rbvm.cisa_kev_evidence")
                    || sql.contains("from rbvm.epss_evidence")
                    || sql.contains("from rbvm.asset_context_evidence")
                    || sql.contains("from rbvm.network_reachability_evidence")
                    || sql.contains("from rbvm.business_impact_evidence");
        }
    }

    private static ResultSet rows(List<Object[]> values) {
        return rows(values.toArray(Object[][]::new));
    }

    private static ResultSet rows(Object[]... values) {
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
