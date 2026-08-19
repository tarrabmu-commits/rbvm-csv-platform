package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionMethodologyPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.AmbiguityHandling.PRESERVE_AMBIGUOUS;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.FreshnessMode.MAX_AGE_SECONDS;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.FreshnessMode.NO_AGE_LIMIT;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.LegacyPriorityHandling.EXCLUDE_LEGACY_PRIORITY_TIER;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.MissingEvidenceHandling.PRESERVE_UNKNOWN;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.SourceSelectionMode.ALL_SOURCES;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.SourceSelectionMode.EXPLICIT_ALLOWLIST;
import static io.rbvm.decision.RbvmDecisionMethodologyPolicy.SubjectScope.FINDING;

public final class PostgresDecisionMethodologyPolicyStoreSelfTest {
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final Instant NOW = Instant.parse("2026-08-19T17:00:00Z");

    private PostgresDecisionMethodologyPolicyStoreSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        installsReplaysConflictsAndRoundTripsImmutablePolicies();
        rejectsCorruptPersistedCanonicalPayload();
        System.out.println("PostgresDecisionMethodologyPolicyStoreSelfTest: PASS");
    }

    private static void installsReplaysConflictsAndRoundTripsImmutablePolicies() throws Exception {
        FakeDatabase database = new FakeDatabase();
        PostgresDecisionMethodologyPolicyStore store = new PostgresDecisionMethodologyPolicyStore(
                database::connection,
                false,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
        assert store.schemaVersion() == 16;

        RbvmDecisionMethodologyPolicy revision1 = policy(1, 2_592_000L);
        DecisionMethodologyPolicyInstallResult inserted = store.install(revision1);
        assert inserted.status() == DecisionMethodologyPolicyInstallResult.Status.INSERTED;
        assert inserted.installedOrReplayed();
        assert database.policies.size() == 1;
        StoredPolicy stored1 = database.policies.get(1);
        assert stored1 != null;
        assert stored1.sha256.equals(revision1.policySha256());
        assert Arrays.equals(stored1.canonicalPayload, revision1.canonicalPayload());
        assert stored1.installedAt.equals(NOW);
        assert database.selections.get(stored1.id).size() == EvidenceDimension.values().length;
        assert database.allowlist(stored1.id, EvidenceDimension.TECHNICAL_SEVERITY)
                .equals(List.of("nvd-cvss-v31", "vendor-advisory"));
        assert database.serializableTransactions == 1;
        assert database.advisoryLocks == 1;
        assert database.commits == 1;
        assert database.catalogUpdates == 0;

        DecisionMethodologyPolicyInstallResult replay = store.install(revision1);
        assert replay.status() == DecisionMethodologyPolicyInstallResult.Status.REPLAYED;
        assert database.policies.size() == 1;
        assert database.policyInserts == 1;
        assert database.selectionInserts == 7;
        assert database.allowlistInserts == 2;
        assert database.commits == 2;
        assert database.catalogUpdates == 0;

        RbvmDecisionMethodologyPolicy conflict = policy(1, 86_400L);
        assert !conflict.policySha256().equals(revision1.policySha256());
        DecisionMethodologyPolicyInstallResult conflictResult = store.install(conflict);
        assert conflictResult.status() == DecisionMethodologyPolicyInstallResult.Status.REVISION_CONFLICT;
        assert conflictResult.existingRevision() == 1;
        assert conflictResult.existingPolicySha256().equals(revision1.policySha256());
        assert database.policyInserts == 1 : "revision conflict must not overwrite policy";
        assert database.selectionInserts == 7;
        assert database.commits == 3;

        RbvmDecisionMethodologyPolicy revision2 = policy(2, 2_592_000L);
        assert !revision2.policySha256().equals(revision1.policySha256())
                : "revision is part of the canonical payload";
        DecisionMethodologyPolicyInstallResult secondRevision = store.install(revision2);
        assert secondRevision.status() == DecisionMethodologyPolicyInstallResult.Status.INSERTED;
        assert database.policies.size() == 2;
        assert database.policyInserts == 2;
        assert database.selectionInserts == 14;
        assert database.allowlistInserts == 4;
        assert database.commits == 4;

        Optional<RbvmDecisionMethodologyPolicy> loaded = store.findByRevision(1);
        assert loaded.isPresent();
        RbvmDecisionMethodologyPolicy roundTrip = loaded.orElseThrow();
        assert roundTrip.revision() == revision1.revision();
        assert roundTrip.policySha256().equals(revision1.policySha256());
        assert Arrays.equals(roundTrip.canonicalPayload(), revision1.canonicalPayload());
        assert roundTrip.evidencePolicies().equals(revision1.evidencePolicies());
        assert store.findByRevision(99).isEmpty();
        assert database.rollbacks == 0;
        assert database.catalogUpdates == 0;
    }

    private static void rejectsCorruptPersistedCanonicalPayload() throws Exception {
        FakeDatabase database = new FakeDatabase();
        PostgresDecisionMethodologyPolicyStore store = new PostgresDecisionMethodologyPolicyStore(
                database::connection,
                false,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
        RbvmDecisionMethodologyPolicy policy = policy(3, 86_400L);
        store.install(policy);
        StoredPolicy stored = database.policies.get(3);
        byte[] corrupt = stored.canonicalPayload.clone();
        corrupt[corrupt.length - 1] ^= 0x01;
        database.policies.put(3, stored.withCanonicalPayload(corrupt));

        boolean rejected = false;
        try {
            store.findByRevision(3);
        } catch (java.io.IOException expected) {
            rejected = expected.getMessage().contains("canonical payload");
        }
        assert rejected : "stored canonical payload corruption must be detected";
    }

    private static RbvmDecisionMethodologyPolicy policy(int revision, long cvssMaximumAgeSeconds) {
        EnumMap<EvidenceDimension, EvidenceSelectionPolicy> selections =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            selections.put(
                    dimension,
                    new EvidenceSelectionPolicy(
                            dimension,
                            ALL_SOURCES,
                            List.of(),
                            NO_AGE_LIMIT,
                            null
                    )
            );
        }
        selections.put(
                EvidenceDimension.TECHNICAL_SEVERITY,
                new EvidenceSelectionPolicy(
                        EvidenceDimension.TECHNICAL_SEVERITY,
                        EXPLICIT_ALLOWLIST,
                        List.of("vendor-advisory", "nvd-cvss-v31"),
                        MAX_AGE_SECONDS,
                        cvssMaximumAgeSeconds
                )
        );
        return RbvmDecisionMethodologyPolicy.create(
                revision,
                FINDING,
                PRESERVE_UNKNOWN,
                PRESERVE_AMBIGUOUS,
                EXCLUDE_LEGACY_PRIORITY_TIER,
                selections
        );
    }

    private static final class FakeDatabase {
        private final Map<Integer, StoredPolicy> policies = new HashMap<>();
        private final Map<UUID, Map<EvidenceDimension, StoredSelection>> selections = new HashMap<>();
        private final Map<String, List<String>> allowlists = new HashMap<>();
        private int policyInserts;
        private int selectionInserts;
        private int allowlistInserts;
        private int commits;
        private int rollbacks;
        private int serializableTransactions;
        private int advisoryLocks;
        private int catalogUpdates;

        private Connection connection() {
            return proxy(Connection.class, (proxy, method, args) -> switch (method.getName()) {
                case "createStatement" -> statement();
                case "prepareStatement" -> prepared((String) args[0]);
                case "setTransactionIsolation" -> {
                    if ((Integer) args[0] == Connection.TRANSACTION_SERIALIZABLE) {
                        serializableTransactions++;
                    }
                    yield null;
                }
                case "setAutoCommit", "close" -> null;
                case "commit" -> { commits++; yield null; }
                case "rollback" -> { rollbacks++; yield null; }
                case "isClosed" -> false;
                default -> defaultValue(method.getReturnType());
            });
        }

        private Statement statement() {
            return proxy(Statement.class, (proxy, method, args) -> switch (method.getName()) {
                case "executeQuery" -> rows(new Object[]{16});
                case "close" -> null;
                default -> defaultValue(method.getReturnType());
            });
        }

        private PreparedStatement prepared(String sql) {
            Map<Integer, Object> parameters = new HashMap<>();
            return proxy(PreparedStatement.class, (proxy, method, args) -> {
                String name = method.getName();
                if (name.startsWith("set") && args != null && args.length >= 2
                        && args[0] instanceof Integer index) {
                    parameters.put(index, args[1]);
                    return null;
                }
                return switch (name) {
                    case "execute" -> {
                        if (sql.contains("pg_advisory_xact_lock")) advisoryLocks++;
                        yield false;
                    }
                    case "executeQuery" -> query(sql, parameters);
                    case "executeUpdate" -> update(sql, parameters);
                    case "close" -> null;
                    default -> defaultValue(method.getReturnType());
                };
            });
        }

        private ResultSet query(String sql, Map<Integer, Object> parameters) {
            if (sql.contains("SELECT id FROM rbvm.tenant")) {
                return rows(new Object[]{TENANT_ID});
            }
            if (sql.contains("FROM rbvm.decision_methodology_policy")) {
                int revision = (Integer) parameters.get(3);
                StoredPolicy stored = policies.get(revision);
                return stored == null ? rows() : rows(stored.asRow());
            }
            if (sql.contains("FROM rbvm.decision_methodology_evidence_policy")) {
                UUID policyId = (UUID) parameters.get(2);
                Map<EvidenceDimension, StoredSelection> values = selections.getOrDefault(
                        policyId,
                        Map.of()
                );
                List<Object[]> result = new ArrayList<>();
                values.entrySet().stream()
                        .sorted(Map.Entry.comparingByKey())
                        .forEach(entry -> result.add(new Object[]{
                                entry.getKey().name(),
                                entry.getValue().sourceSelectionMode,
                                entry.getValue().freshnessMode,
                                entry.getValue().maximumAgeSeconds
                        }));
                return rows(result.toArray(Object[][]::new));
            }
            if (sql.contains("FROM rbvm.decision_methodology_source_allowlist")) {
                UUID policyId = (UUID) parameters.get(2);
                EvidenceDimension dimension = EvidenceDimension.valueOf((String) parameters.get(3));
                List<String> sources = allowlist(policyId, dimension);
                Object[][] result = sources.stream().map(source -> new Object[]{source})
                        .toArray(Object[][]::new);
                return rows(result);
            }
            throw new AssertionError("Unexpected query:\n" + sql);
        }

        private int update(String sql, Map<Integer, Object> parameters) {
            if (sql.contains("INSERT INTO rbvm.decision_methodology_policy")) {
                UUID id = (UUID) parameters.get(1);
                int revision = (Integer) parameters.get(5);
                StoredPolicy stored = new StoredPolicy(
                        id,
                        (String) parameters.get(3),
                        (String) parameters.get(4),
                        revision,
                        (String) parameters.get(6),
                        (String) parameters.get(7),
                        ((byte[]) parameters.get(8)).clone(),
                        (String) parameters.get(9),
                        (String) parameters.get(10),
                        (String) parameters.get(11),
                        (String) parameters.get(12),
                        ((Timestamp) parameters.get(13)).toInstant()
                );
                if (policies.putIfAbsent(revision, stored) != null) {
                    throw new AssertionError("Store attempted duplicate methodology revision insert");
                }
                policyInserts++;
                return 1;
            }
            if (sql.contains("INSERT INTO rbvm.decision_methodology_evidence_policy")) {
                UUID policyId = (UUID) parameters.get(2);
                EvidenceDimension dimension = EvidenceDimension.valueOf((String) parameters.get(3));
                selections.computeIfAbsent(policyId, ignored -> new EnumMap<>(EvidenceDimension.class))
                        .put(dimension, new StoredSelection(
                                (String) parameters.get(4),
                                (String) parameters.get(5),
                                (Long) parameters.get(6)
                        ));
                selectionInserts++;
                return 1;
            }
            if (sql.contains("INSERT INTO rbvm.decision_methodology_source_allowlist")) {
                UUID policyId = (UUID) parameters.get(2);
                EvidenceDimension dimension = EvidenceDimension.valueOf((String) parameters.get(3));
                allowlists.computeIfAbsent(allowlistKey(policyId, dimension), ignored -> new ArrayList<>())
                        .add((String) parameters.get(4));
                allowlists.get(allowlistKey(policyId, dimension)).sort(String::compareTo);
                allowlistInserts++;
                return 1;
            }
            if (sql.contains("UPDATE rbvm.catalog_state")) {
                catalogUpdates++;
                return 1;
            }
            throw new AssertionError("Unexpected update:\n" + sql);
        }

        private List<String> allowlist(UUID policyId, EvidenceDimension dimension) {
            return List.copyOf(allowlists.getOrDefault(allowlistKey(policyId, dimension), List.of()));
        }

        private static String allowlistKey(UUID policyId, EvidenceDimension dimension) {
            return policyId + "|" + dimension;
        }
    }

    private record StoredPolicy(
            UUID id,
            String contractId,
            String semantics,
            int revision,
            String sha256,
            String payloadFormat,
            byte[] canonicalPayload,
            String subjectScope,
            String missingHandling,
            String ambiguityHandling,
            String legacyHandling,
            Instant installedAt
    ) {
        private StoredPolicy {
            canonicalPayload = canonicalPayload.clone();
        }

        private Object[] asRow() {
            return new Object[]{
                    id, contractId, semantics, revision, sha256, payloadFormat,
                    canonicalPayload.clone(), subjectScope, missingHandling,
                    ambiguityHandling, legacyHandling
            };
        }

        private StoredPolicy withCanonicalPayload(byte[] replacement) {
            return new StoredPolicy(
                    id, contractId, semantics, revision, sha256, payloadFormat,
                    replacement, subjectScope, missingHandling, ambiguityHandling,
                    legacyHandling, installedAt
            );
        }
    }

    private record StoredSelection(
            String sourceSelectionMode,
            String freshnessMode,
            Long maximumAgeSeconds
    ) {
    }

    private static ResultSet rows(Object[]... values) {
        int[] cursor = {-1};
        return proxy(ResultSet.class, (proxy, method, args) -> switch (method.getName()) {
            case "next" -> ++cursor[0] < values.length;
            case "getObject" -> values[cursor[0]][(Integer) args[0] - 1];
            case "getString" -> {
                Object value = values[cursor[0]][(Integer) args[0] - 1];
                yield value == null ? null : value.toString();
            }
            case "getInt" -> ((Number) values[cursor[0]][(Integer) args[0] - 1]).intValue();
            case "getLong" -> ((Number) values[cursor[0]][(Integer) args[0] - 1]).longValue();
            case "getBytes" -> ((byte[]) values[cursor[0]][(Integer) args[0] - 1]).clone();
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
