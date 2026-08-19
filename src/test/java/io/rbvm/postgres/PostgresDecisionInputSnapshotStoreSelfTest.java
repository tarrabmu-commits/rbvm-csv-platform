package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
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

public final class PostgresDecisionInputSnapshotStoreSelfTest {
    private static final UUID TENANT_ID = UUID.fromString("10000000-0000-5000-8000-000000000001");
    private static final UUID FINDING_ID = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID POLICY_ID = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final String POLICY_SHA = "a".repeat(64);
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-19T18:00:00Z");
    private static final Instant PERSISTED_AT = Instant.parse("2026-08-19T18:00:05Z");

    private PostgresDecisionInputSnapshotStoreSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        installsReplaysConflictsAndRoundTripsSnapshots();
        rejectsUnknownPolicyAndFinding();
        rejectsCorruptPersistedCanonicalPayload();
        System.out.println("PostgresDecisionInputSnapshotStoreSelfTest: PASS");
    }

    private static void installsReplaysConflictsAndRoundTripsSnapshots() throws Exception {
        FakeDatabase database = new FakeDatabase();
        database.registeredPolicies.put(policyKey(4, POLICY_SHA), POLICY_ID);
        database.findings.put(FINDING_ID, true);
        PostgresDecisionInputSnapshotStore store = new PostgresDecisionInputSnapshotStore(
                database::connection,
                false,
                Clock.fixed(PERSISTED_AT, ZoneOffset.UTC)
        );
        assert store.schemaVersion() == 17;

        RbvmDecisionInputSnapshot snapshot = snapshot(EVALUATED_AT, false);
        DecisionInputSnapshotInstallResult inserted = store.install(snapshot);
        assert inserted.status() == DecisionInputSnapshotInstallResult.Status.INSERTED;
        assert inserted.installedOrReplayed();
        assert database.snapshots.size() == 1;
        StoredSnapshot stored = database.snapshotsBySha.get(snapshot.snapshotSha256());
        assert stored != null;
        assert stored.findingId.equals(FINDING_ID);
        assert stored.policyId.equals(POLICY_ID);
        assert stored.methodologyRevision == 4;
        assert stored.methodologyPolicySha256.equals(POLICY_SHA);
        assert stored.persistedAt.equals(PERSISTED_AT);
        assert Arrays.equals(stored.canonicalPayload, snapshot.canonicalPayload());
        assert database.dimensions.get(stored.id).size() == EvidenceDimension.values().length;
        assert database.referenceCount(stored.id) == 7;
        assert database.serializableTransactions == 1;
        assert database.advisoryLocks == 1;
        assert database.commits == 1;
        assert database.catalogUpdates == 0;

        DecisionInputSnapshotInstallResult replay = store.install(snapshot);
        assert replay.status() == DecisionInputSnapshotInstallResult.Status.REPLAYED;
        assert database.snapshotInserts == 1;
        assert database.dimensionInserts == 7;
        assert database.referenceInserts == 7;
        assert database.commits == 2;

        RbvmDecisionInputSnapshot conflict = snapshot(EVALUATED_AT, true);
        assert !conflict.snapshotSha256().equals(snapshot.snapshotSha256());
        DecisionInputSnapshotInstallResult conflictResult = store.install(conflict);
        assert conflictResult.status() == DecisionInputSnapshotInstallResult.Status.EVALUATION_CONFLICT;
        assert conflictResult.existingSnapshotSha256().equals(snapshot.snapshotSha256());
        assert database.snapshotInserts == 1 : "evaluation conflict must not overwrite snapshot";
        assert database.commits == 3;

        RbvmDecisionInputSnapshot later = snapshot(EVALUATED_AT.plusSeconds(60), false);
        DecisionInputSnapshotInstallResult laterResult = store.install(later);
        assert laterResult.status() == DecisionInputSnapshotInstallResult.Status.INSERTED;
        assert database.snapshots.size() == 2;
        assert database.snapshotInserts == 2;
        assert database.dimensionInserts == 14;
        assert database.referenceInserts == 14;
        assert database.commits == 4;

        Optional<RbvmDecisionInputSnapshot> loaded = store.findBySha256(snapshot.snapshotSha256());
        assert loaded.isPresent();
        RbvmDecisionInputSnapshot roundTrip = loaded.orElseThrow();
        assert roundTrip.findingId().equals(snapshot.findingId());
        assert roundTrip.methodologyRevision() == snapshot.methodologyRevision();
        assert roundTrip.methodologyPolicySha256().equals(snapshot.methodologyPolicySha256());
        assert roundTrip.snapshotSha256().equals(snapshot.snapshotSha256());
        assert Arrays.equals(roundTrip.canonicalPayload(), snapshot.canonicalPayload());
        assert roundTrip.dimensions().equals(snapshot.dimensions());
        assert store.findBySha256("f".repeat(64)).isEmpty();
        assert database.rollbacks == 0;
        assert database.catalogUpdates == 0;
    }

    private static void rejectsUnknownPolicyAndFinding() throws Exception {
        FakeDatabase unknownPolicy = new FakeDatabase();
        unknownPolicy.findings.put(FINDING_ID, true);
        PostgresDecisionInputSnapshotStore policyStore = store(unknownPolicy);
        boolean policyRejected = false;
        try {
            policyStore.install(snapshot(EVALUATED_AT, false));
        } catch (java.io.IOException expected) {
            policyRejected = expected.getMessage().contains("unregistered methodology");
        }
        assert policyRejected;
        assert unknownPolicy.snapshotInserts == 0;
        assert unknownPolicy.rollbacks == 1;

        FakeDatabase missingFinding = new FakeDatabase();
        missingFinding.registeredPolicies.put(policyKey(4, POLICY_SHA), POLICY_ID);
        PostgresDecisionInputSnapshotStore findingStore = store(missingFinding);
        boolean findingRejected = false;
        try {
            findingStore.install(snapshot(EVALUATED_AT, false));
        } catch (java.io.IOException expected) {
            findingRejected = expected.getMessage().contains("Finding_ID");
        }
        assert findingRejected;
        assert missingFinding.snapshotInserts == 0;
        assert missingFinding.rollbacks == 1;
    }

    private static void rejectsCorruptPersistedCanonicalPayload() throws Exception {
        FakeDatabase database = new FakeDatabase();
        database.registeredPolicies.put(policyKey(4, POLICY_SHA), POLICY_ID);
        database.findings.put(FINDING_ID, true);
        PostgresDecisionInputSnapshotStore store = store(database);
        RbvmDecisionInputSnapshot snapshot = snapshot(EVALUATED_AT, false);
        store.install(snapshot);
        StoredSnapshot stored = database.snapshotsBySha.get(snapshot.snapshotSha256());
        byte[] corrupt = stored.canonicalPayload.clone();
        corrupt[corrupt.length - 1] ^= 0x01;
        StoredSnapshot replacement = stored.withCanonicalPayload(corrupt);
        database.snapshotsBySha.put(snapshot.snapshotSha256(), replacement);
        database.snapshots.put(evaluationKey(FINDING_ID, POLICY_ID, EVALUATED_AT), replacement);

        boolean rejected = false;
        try {
            store.findBySha256(snapshot.snapshotSha256());
        } catch (java.io.IOException expected) {
            rejected = expected.getMessage().contains("canonical payload");
        }
        assert rejected : "stored decision-input canonical payload corruption must be detected";
    }

    private static PostgresDecisionInputSnapshotStore store(FakeDatabase database) throws Exception {
        return new PostgresDecisionInputSnapshotStore(
                database::connection,
                false,
                Clock.fixed(PERSISTED_AT, ZoneOffset.UTC)
        );
    }

    private static RbvmDecisionInputSnapshot snapshot(Instant evaluatedAt, boolean alternate) {
        EnumMap<EvidenceDimension, DimensionInput> dimensions = new EnumMap<>(EvidenceDimension.class);
        int index = 1;
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            DimensionState state = dimension == EvidenceDimension.TECHNICAL_SEVERITY
                    ? DimensionState.MISSING : DimensionState.PRESENT;
            List<EvidenceReference> references = state == DimensionState.MISSING
                    ? List.of()
                    : List.of(reference(dimension, index++, evaluatedAt.minusSeconds(3600)));
            dimensions.put(dimension, new DimensionInput(dimension, state, references));
        }
        if (alternate) {
            EvidenceDimension dimension = EvidenceDimension.NETWORK_REACHABILITY;
            dimensions.put(
                    dimension,
                    new DimensionInput(
                            dimension,
                            DimensionState.STALE,
                            dimensions.get(dimension).evidenceReferences()
                    )
            );
        }
        return RbvmDecisionInputSnapshot.create(
                FINDING_ID,
                4,
                POLICY_SHA,
                evaluatedAt,
                dimensions
        );
    }

    private static EvidenceReference reference(
            EvidenceDimension dimension,
            int index,
            Instant observedAt
    ) {
        return new EvidenceReference(
                dimension,
                UUID.nameUUIDFromBytes((dimension.name() + index).getBytes(StandardCharsets.UTF_8)),
                Integer.toHexString(index).substring(0, 1).repeat(64),
                "source-" + dimension.name().toLowerCase(java.util.Locale.ROOT),
                observedAt
        );
    }

    private static final class FakeDatabase {
        private final Map<String, UUID> registeredPolicies = new HashMap<>();
        private final Map<UUID, Boolean> findings = new HashMap<>();
        private final Map<String, StoredSnapshot> snapshots = new HashMap<>();
        private final Map<String, StoredSnapshot> snapshotsBySha = new HashMap<>();
        private final Map<UUID, Map<EvidenceDimension, DimensionState>> dimensions = new HashMap<>();
        private final Map<String, List<StoredReference>> references = new HashMap<>();
        private int snapshotInserts;
        private int dimensionInserts;
        private int referenceInserts;
        private int serializableTransactions;
        private int advisoryLocks;
        private int commits;
        private int rollbacks;
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
                case "executeQuery" -> rows(new Object[]{17});
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
                UUID id = registeredPolicies.get(policyKey(
                        (Integer) parameters.get(3),
                        (String) parameters.get(4)
                ));
                return id == null ? rows() : rows(new Object[]{id});
            }
            if (sql.contains("SELECT 1 FROM rbvm.exposure")) {
                UUID finding = (UUID) parameters.get(2);
                return findings.containsKey(finding) ? rows(new Object[]{1}) : rows();
            }
            if (sql.contains("FROM rbvm.decision_input_snapshot")
                    && sql.contains("methodology_policy_id")) {
                String key = evaluationKey(
                        (UUID) parameters.get(2),
                        (UUID) parameters.get(3),
                        ((Timestamp) parameters.get(4)).toInstant()
                );
                StoredSnapshot stored = snapshots.get(key);
                return stored == null ? rows() : rows(stored.asReadRow());
            }
            if (sql.contains("FROM rbvm.decision_input_snapshot")
                    && sql.contains("snapshot_sha256 = ?")) {
                StoredSnapshot stored = snapshotsBySha.get((String) parameters.get(2));
                return stored == null ? rows() : rows(stored.asReadRow());
            }
            if (sql.contains("FROM rbvm.decision_input_dimension")) {
                UUID snapshotId = (UUID) parameters.get(2);
                List<Object[]> result = new ArrayList<>();
                dimensions.getOrDefault(snapshotId, Map.of()).entrySet().stream()
                        .sorted(Map.Entry.comparingByKey())
                        .forEach(entry -> result.add(new Object[]{
                                entry.getKey().name(), entry.getValue().name()
                        }));
                return rows(result.toArray(Object[][]::new));
            }
            if (sql.contains("FROM rbvm.decision_input_evidence_reference")) {
                UUID snapshotId = (UUID) parameters.get(2);
                EvidenceDimension dimension = EvidenceDimension.valueOf((String) parameters.get(3));
                List<StoredReference> values = references.getOrDefault(
                        referenceKey(snapshotId, dimension), List.of());
                Object[][] result = values.stream()
                        .sorted(java.util.Comparator.comparing(StoredReference::evidenceId))
                        .map(StoredReference::asRow)
                        .toArray(Object[][]::new);
                return rows(result);
            }
            throw new AssertionError("Unexpected query:\n" + sql);
        }

        private int update(String sql, Map<Integer, Object> parameters) {
            if (sql.contains("INSERT INTO rbvm.decision_input_snapshot")) {
                StoredSnapshot stored = new StoredSnapshot(
                        (UUID) parameters.get(1),
                        (UUID) parameters.get(3),
                        (UUID) parameters.get(4),
                        (Integer) parameters.get(5),
                        (String) parameters.get(6),
                        (String) parameters.get(7),
                        (String) parameters.get(8),
                        (String) parameters.get(9),
                        (String) parameters.get(10),
                        ((byte[]) parameters.get(11)).clone(),
                        ((Timestamp) parameters.get(12)).toInstant(),
                        ((Timestamp) parameters.get(13)).toInstant()
                );
                snapshots.put(
                        evaluationKey(stored.findingId, stored.policyId, stored.evaluatedAt), stored);
                snapshotsBySha.put(stored.snapshotSha256, stored);
                snapshotInserts++;
                return 1;
            }
            if (sql.contains("INSERT INTO rbvm.decision_input_dimension")) {
                UUID snapshotId = (UUID) parameters.get(2);
                EvidenceDimension dimension = EvidenceDimension.valueOf((String) parameters.get(3));
                DimensionState state = DimensionState.valueOf((String) parameters.get(4));
                dimensions.computeIfAbsent(snapshotId, ignored -> new EnumMap<>(EvidenceDimension.class))
                        .put(dimension, state);
                dimensionInserts++;
                return 1;
            }
            if (sql.contains("INSERT INTO rbvm.decision_input_evidence_reference")) {
                UUID snapshotId = (UUID) parameters.get(2);
                EvidenceDimension dimension = EvidenceDimension.valueOf((String) parameters.get(3));
                references.computeIfAbsent(referenceKey(snapshotId, dimension), ignored -> new ArrayList<>())
                        .add(new StoredReference(
                                (UUID) parameters.get(4),
                                (String) parameters.get(5),
                                (String) parameters.get(6),
                                ((Timestamp) parameters.get(7)).toInstant()
                        ));
                referenceInserts++;
                return 1;
            }
            if (sql.contains("UPDATE rbvm.catalog_state")) {
                catalogUpdates++;
                return 1;
            }
            throw new AssertionError("Unexpected update:\n" + sql);
        }

        private int referenceCount(UUID snapshotId) {
            return references.entrySet().stream()
                    .filter(entry -> entry.getKey().startsWith(snapshotId.toString() + "|"))
                    .mapToInt(entry -> entry.getValue().size())
                    .sum();
        }
    }

    private record StoredSnapshot(
            UUID id,
            UUID findingId,
            UUID policyId,
            int methodologyRevision,
            String methodologyPolicySha256,
            String contractId,
            String semantics,
            String snapshotSha256,
            String canonicalPayloadFormat,
            byte[] canonicalPayload,
            Instant evaluatedAt,
            Instant persistedAt
    ) {
        private StoredSnapshot {
            canonicalPayload = canonicalPayload.clone();
        }

        private Object[] asReadRow() {
            return new Object[]{
                    id, findingId, methodologyRevision, methodologyPolicySha256,
                    contractId, semantics, snapshotSha256, canonicalPayloadFormat,
                    canonicalPayload.clone(), Timestamp.from(evaluatedAt)
            };
        }

        private StoredSnapshot withCanonicalPayload(byte[] replacement) {
            return new StoredSnapshot(
                    id, findingId, policyId, methodologyRevision, methodologyPolicySha256,
                    contractId, semantics, snapshotSha256, canonicalPayloadFormat,
                    replacement, evaluatedAt, persistedAt
            );
        }
    }

    private record StoredReference(
            UUID evidenceId,
            String evidenceSha256,
            String evidenceSource,
            Instant observedAt
    ) {
        private Object[] asRow() {
            return new Object[]{
                    evidenceId, evidenceSha256, evidenceSource, Timestamp.from(observedAt)
            };
        }
    }

    private static String policyKey(int revision, String sha) {
        return revision + "|" + sha;
    }

    private static String evaluationKey(UUID findingId, UUID policyId, Instant evaluatedAt) {
        return findingId + "|" + policyId + "|" + evaluatedAt;
    }

    private static String referenceKey(UUID snapshotId, EvidenceDimension dimension) {
        return snapshotId + "|" + dimension;
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
            case "getBytes" -> ((byte[]) values[cursor[0]][(Integer) args[0] - 1]).clone();
            case "getTimestamp" -> values[cursor[0]][(Integer) args[0] - 1];
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
