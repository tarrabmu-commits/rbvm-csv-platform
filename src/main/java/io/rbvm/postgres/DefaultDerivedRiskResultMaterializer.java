package io.rbvm.postgres;

import io.rbvm.decision.DecisionInputEvidenceResolver;
import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDerivedRiskCanonicalResult;
import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.decision.RbvmResolvedDecisionInput;

import java.io.IOException;
import java.util.Objects;

/**
 * Exact-snapshot, exact-methodology derived-risk materialization with no hidden default selection.
 */
public final class DefaultDerivedRiskResultMaterializer implements DerivedRiskResultMaterializer {
    private final DecisionInputSnapshotStore snapshots;
    private final DecisionInputEvidenceResolver evidenceResolver;
    private final DerivedRiskResultStore results;
    private final DerivedRiskResultReplayVerifier replayVerifier;

    public DefaultDerivedRiskResultMaterializer(
            DecisionInputSnapshotStore snapshots,
            DecisionInputEvidenceResolver evidenceResolver,
            DerivedRiskResultStore results,
            DerivedRiskResultReplayVerifier replayVerifier
    ) {
        this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
        this.evidenceResolver = Objects.requireNonNull(evidenceResolver, "evidenceResolver");
        this.results = Objects.requireNonNull(results, "results");
        this.replayVerifier = Objects.requireNonNull(replayVerifier, "replayVerifier");
    }

    @Override
    public DerivedRiskResultMaterializationResult materialize(
            String inputSnapshotSha256,
            String methodologyId,
            String methodologySha256
    ) throws IOException {
        String snapshotSha = requireSha(inputSnapshotSha256, "inputSnapshotSha256");
        String methodologySha = requireSha(methodologySha256, "methodologySha256");
        String requestedMethodologyId = requireText(methodologyId, "methodologyId");

        RbvmDecisionInputSnapshot snapshot = snapshots.findBySha256(snapshotSha)
                .orElseThrow(() -> new SnapshotNotFoundException(snapshotSha));
        if (!snapshot.isV3()) {
            throw new UnsupportedSnapshotContractException(snapshot.contractId());
        }
        if (!snapshot.snapshotSha256().equals(snapshotSha)) {
            throw new IOException(
                    "Decision Input store returned a snapshot that does not match the requested identity"
            );
        }

        RbvmDerivedRiskMethodology methodology = RbvmDerivedRiskMethodologyCatalog
                .find(requestedMethodologyId)
                .orElseThrow(() -> new MethodologyNotFoundException(requestedMethodologyId));
        RbvmDerivedRiskMethodology.Definition definition = methodology.definition();
        if (!definition.methodologyId().equals(requestedMethodologyId)
                || !definition.methodologySha256().equals(methodologySha)) {
            throw new MethodologyIdentityMismatchException(
                    requestedMethodologyId,
                    methodologySha,
                    definition.methodologyId(),
                    definition.methodologySha256()
            );
        }

        RbvmResolvedDecisionInput resolved = evidenceResolver.resolve(snapshot);
        RbvmDerivedRiskCanonicalResult canonicalResult = RbvmDerivedRiskCanonicalResult.from(
                methodology.evaluate(resolved)
        );
        var evaluation = canonicalResult.evaluation();
        if (!snapshotSha.equals(evaluation.inputSnapshotSha256())
                || !snapshot.findingId().equals(evaluation.findingId())
                || !definition.equals(evaluation.definition())) {
            throw new IOException(
                    "Derived risk evaluation does not match the requested snapshot/methodology identity"
            );
        }

        DerivedRiskResultInstallResult installResult = results.install(canonicalResult);
        if (installResult.status() == DerivedRiskResultInstallResult.Status.RESULT_CONFLICT) {
            throw new ResultConflictException(
                    snapshotSha,
                    definition.methodologyId(),
                    definition.methodologySha256(),
                    canonicalResult.canonicalSha256(),
                    installResult.persistedResultSha256()
            );
        }
        if (!installResult.installedOrReplayed()) {
            throw new IOException(
                    "Derived risk result install returned an unsupported materialization state"
            );
        }

        StoredDerivedRiskResult stored = results
                .findByResultSha256(canonicalResult.canonicalSha256())
                .orElseThrow(() -> new IOException(
                        "Derived risk materialization installed a result that cannot be reloaded by exact identity"
                ));
        RbvmDerivedRiskCanonicalResult replayed = replayVerifier.replay(stored);
        if (!canonicalResult.canonicalSha256().equals(replayed.canonicalSha256())) {
            throw new IOException(
                    "Derived risk materialization replay produced a different canonical result identity"
            );
        }
        return new DerivedRiskResultMaterializationResult(
                canonicalResult,
                installResult,
                stored
        );
    }

    private static String requireSha(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be a lowercase SHA-256");
        }
        return value;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank() || value.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " must be non-empty text");
        }
        return value.trim();
    }

    public static final class SnapshotNotFoundException extends IOException {
        private static final long serialVersionUID = 1L;
        private final String inputSnapshotSha256;

        SnapshotNotFoundException(String inputSnapshotSha256) {
            super("Persisted Decision Input snapshot does not exist for the requested identity");
            this.inputSnapshotSha256 = inputSnapshotSha256;
        }

        public String inputSnapshotSha256() {
            return inputSnapshotSha256;
        }
    }

    public static final class UnsupportedSnapshotContractException extends IOException {
        private static final long serialVersionUID = 1L;
        private final String contractId;

        UnsupportedSnapshotContractException(String contractId) {
            super("Derived risk materialization requires RBVM_DECISION_INPUT_SNAPSHOT_V3");
            this.contractId = Objects.requireNonNull(contractId, "contractId");
        }

        public String contractId() {
            return contractId;
        }
    }

    public static final class MethodologyNotFoundException extends IOException {
        private static final long serialVersionUID = 1L;
        private final String methodologyId;

        MethodologyNotFoundException(String methodologyId) {
            super("Requested derived risk methodology is not implemented");
            this.methodologyId = methodologyId;
        }

        public String methodologyId() {
            return methodologyId;
        }
    }

    public static final class MethodologyIdentityMismatchException extends IOException {
        private static final long serialVersionUID = 1L;
        private final String requestedMethodologyId;
        private final String requestedMethodologySha256;
        private final String implementedMethodologyId;
        private final String implementedMethodologySha256;

        MethodologyIdentityMismatchException(
                String requestedMethodologyId,
                String requestedMethodologySha256,
                String implementedMethodologyId,
                String implementedMethodologySha256
        ) {
            super("Requested derived risk methodology identity does not match implementation");
            this.requestedMethodologyId = requestedMethodologyId;
            this.requestedMethodologySha256 = requestedMethodologySha256;
            this.implementedMethodologyId = implementedMethodologyId;
            this.implementedMethodologySha256 = implementedMethodologySha256;
        }

        public String requestedMethodologyId() {
            return requestedMethodologyId;
        }

        public String requestedMethodologySha256() {
            return requestedMethodologySha256;
        }

        public String implementedMethodologyId() {
            return implementedMethodologyId;
        }

        public String implementedMethodologySha256() {
            return implementedMethodologySha256;
        }
    }

    public static final class ResultConflictException extends IOException {
        private static final long serialVersionUID = 1L;
        private final String inputSnapshotSha256;
        private final String methodologyId;
        private final String methodologySha256;
        private final String requestedResultSha256;
        private final String existingResultSha256;

        ResultConflictException(
                String inputSnapshotSha256,
                String methodologyId,
                String methodologySha256,
                String requestedResultSha256,
                String existingResultSha256
        ) {
            super("Persisted derived risk result conflicts with deterministic materialization output");
            this.inputSnapshotSha256 = inputSnapshotSha256;
            this.methodologyId = methodologyId;
            this.methodologySha256 = methodologySha256;
            this.requestedResultSha256 = requestedResultSha256;
            this.existingResultSha256 = existingResultSha256;
        }

        public String inputSnapshotSha256() { return inputSnapshotSha256; }
        public String methodologyId() { return methodologyId; }
        public String methodologySha256() { return methodologySha256; }
        public String requestedResultSha256() { return requestedResultSha256; }
        public String existingResultSha256() { return existingResultSha256; }
    }
}
