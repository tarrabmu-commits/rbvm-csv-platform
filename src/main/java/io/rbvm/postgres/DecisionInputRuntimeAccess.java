package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Exact Decision Input workflow access for Formula-facing operator transport.
 *
 * <p>This boundary never chooses a methodology, evaluation time, Finding, or snapshot on behalf of
 * the caller. Lists are histories/catalogs only; no row is labeled current/latest/preferred.</p>
 */
public final class DecisionInputRuntimeAccess {
    private final DecisionMethodologyPolicyStore methodologies;
    private final DecisionInputSnapshotStore snapshots;
    private final DecisionInputSnapshotMaterializer materializer;
    private final HistoryReader historyReader;
    private final MethodologyCatalog methodologyCatalog;

    public DecisionInputRuntimeAccess(
            DecisionMethodologyPolicyStore methodologies,
            DecisionInputSnapshotStore snapshots,
            DecisionInputSnapshotMaterializer materializer,
            HistoryReader historyReader,
            MethodologyCatalog methodologyCatalog
    ) {
        this.methodologies = Objects.requireNonNull(methodologies, "methodologies");
        this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
        this.materializer = Objects.requireNonNull(materializer, "materializer");
        this.historyReader = Objects.requireNonNull(historyReader, "historyReader");
        this.methodologyCatalog = Objects.requireNonNull(methodologyCatalog, "methodologyCatalog");
    }

    public Optional<RbvmDecisionInputSnapshot> findSnapshot(String snapshotSha256)
            throws IOException {
        return snapshots.findBySha256(snapshotSha256);
    }

    public SnapshotHistoryPage history(
            UUID findingId,
            int limit,
            Instant beforeEvaluatedAt,
            String beforeSnapshotSha256
    ) throws IOException {
        return historyReader.history(
                findingId,
                limit,
                beforeEvaluatedAt,
                beforeSnapshotSha256
        );
    }

    public Optional<RbvmDecisionMethodologyPolicy> findMethodology(int revision)
            throws IOException {
        return methodologies.findByRevision(revision);
    }

    public MethodologyPage methodologies(int limit, Integer afterRevision) throws IOException {
        return methodologyCatalog.list(limit, afterRevision);
    }

    public DecisionInputSnapshotMaterializationResult materialize(
            UUID findingId,
            int methodologyRevision,
            String methodologyPolicySha256,
            Instant evaluatedAt
    ) throws IOException {
        RbvmDecisionMethodologyPolicy methodology = methodologies
                .findByRevision(methodologyRevision)
                .orElseThrow(() -> new MethodologyNotFoundException(methodologyRevision));
        if (!methodology.policySha256().equals(methodologyPolicySha256)) {
            throw new MethodologyIdentityMismatchException(
                    methodologyRevision,
                    methodology.policySha256(),
                    methodologyPolicySha256
            );
        }

        DecisionInputSnapshotMaterializationResult result = materializer.materialize(
                findingId,
                methodologyRevision,
                methodologyPolicySha256,
                evaluatedAt
        );
        if (result.installResult().status()
                == DecisionInputSnapshotInstallResult.Status.EVALUATION_CONFLICT) {
            throw new EvaluationConflictException(
                    result.installResult().requestedSnapshotSha256(),
                    result.installResult().existingSnapshotSha256()
            );
        }
        if (!result.installedOrReplayed()) {
            throw new IOException(
                    "Decision Input materialization returned an unsupported persistence outcome"
            );
        }
        if (!result.snapshot().isV3()) {
            throw new IOException(
                    "Formula-facing Decision Input materialization requires Snapshot V3"
            );
        }

        RbvmDecisionInputSnapshot stored = snapshots
                .findBySha256(result.snapshot().snapshotSha256())
                .orElseThrow(() -> new IOException(
                        "Materialized Decision Input snapshot could not be reloaded by exact SHA"
                ));
        if (!stored.snapshotSha256().equals(result.snapshot().snapshotSha256())
                || !java.util.Arrays.equals(
                        stored.canonicalPayload(),
                        result.snapshot().canonicalPayload()
                )) {
            throw new IOException(
                    "Reloaded Decision Input snapshot does not match materialized canonical content"
            );
        }
        return new DecisionInputSnapshotMaterializationResult(stored, result.installResult());
    }

    public interface HistoryReader {
        SnapshotHistoryPage history(
                UUID findingId,
                int limit,
                Instant beforeEvaluatedAt,
                String beforeSnapshotSha256
        ) throws IOException;
    }

    public interface MethodologyCatalog {
        MethodologyPage list(int limit, Integer afterRevision) throws IOException;
    }

    public record SnapshotHistoryPage(
            List<RbvmDecisionInputSnapshot> snapshots,
            Instant nextBeforeEvaluatedAt,
            String nextBeforeSnapshotSha256
    ) {
        public SnapshotHistoryPage {
            snapshots = List.copyOf(Objects.requireNonNull(snapshots, "snapshots"));
            if ((nextBeforeEvaluatedAt == null) != (nextBeforeSnapshotSha256 == null)) {
                throw new IllegalArgumentException(
                        "Decision Input history cursor fields must both be null or both be present"
                );
            }
            if (nextBeforeSnapshotSha256 != null
                    && !nextBeforeSnapshotSha256.matches("[a-f0-9]{64}")) {
                throw new IllegalArgumentException(
                        "nextBeforeSnapshotSha256 must be lowercase SHA-256"
                );
            }
        }
    }

    public record MethodologyPage(
            List<RbvmDecisionMethodologyPolicy> methodologies,
            Integer nextAfterRevision
    ) {
        public MethodologyPage {
            methodologies = List.copyOf(Objects.requireNonNull(methodologies, "methodologies"));
            if (nextAfterRevision != null && nextAfterRevision < 1) {
                throw new IllegalArgumentException("nextAfterRevision must be positive");
            }
        }
    }

    public static final class MethodologyNotFoundException extends IOException {
        private static final long serialVersionUID = 1L;

        public MethodologyNotFoundException(int revision) {
            super("Decision methodology revision " + revision + " is not registered");
        }
    }

    public static final class MethodologyIdentityMismatchException extends IOException {
        private static final long serialVersionUID = 1L;

        public MethodologyIdentityMismatchException(
                int revision,
                String registeredSha256,
                String requestedSha256
        ) {
            super("Decision methodology revision " + revision
                    + " is registered with SHA " + registeredSha256
                    + " and does not match requested SHA " + requestedSha256);
        }
    }

    public static final class EvaluationConflictException extends IOException {
        private static final long serialVersionUID = 1L;

        private final String requestedSnapshotSha256;
        private final String existingSnapshotSha256;

        public EvaluationConflictException(
                String requestedSnapshotSha256,
                String existingSnapshotSha256
        ) {
            super("A different Decision Input snapshot already exists for the exact "
                    + "Finding/methodology/evaluatedAt identity");
            this.requestedSnapshotSha256 = Objects.requireNonNull(
                    requestedSnapshotSha256,
                    "requestedSnapshotSha256"
            );
            this.existingSnapshotSha256 = Objects.requireNonNull(
                    existingSnapshotSha256,
                    "existingSnapshotSha256"
            );
        }

        public String requestedSnapshotSha256() {
            return requestedSnapshotSha256;
        }

        public String existingSnapshotSha256() {
            return existingSnapshotSha256;
        }
    }
}
