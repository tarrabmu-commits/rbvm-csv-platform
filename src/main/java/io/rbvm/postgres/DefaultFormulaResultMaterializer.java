package io.rbvm.postgres;

import io.rbvm.decision.DecisionInputEvidenceResolver;
import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmFormulaV1Explanation;
import io.rbvm.decision.RbvmResolvedDecisionInput;

import java.io.IOException;
import java.util.Objects;

/**
 * Exact-snapshot Formula V1 materialization with no Decision Input build or current-state selection.
 *
 * <p>The caller supplies only the immutable SHA-256 identity of an already-persisted Decision Input
 * V3 snapshot. The materializer resolves exactly that snapshot's captured native evidence and
 * bindings, evaluates Formula V1, installs the canonical explanation append-only, reloads the exact
 * persisted result, and requires deterministic historical replay before returning.</p>
 */
public final class DefaultFormulaResultMaterializer implements FormulaResultMaterializer {
    private final DecisionInputSnapshotStore snapshots;
    private final DecisionInputEvidenceResolver evidenceResolver;
    private final FormulaResultStore results;
    private final FormulaResultReplayVerifier replayVerifier;

    public DefaultFormulaResultMaterializer(
            DecisionInputSnapshotStore snapshots,
            DecisionInputEvidenceResolver evidenceResolver,
            FormulaResultStore results,
            FormulaResultReplayVerifier replayVerifier
    ) {
        this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
        this.evidenceResolver = Objects.requireNonNull(evidenceResolver, "evidenceResolver");
        this.results = Objects.requireNonNull(results, "results");
        this.replayVerifier = Objects.requireNonNull(replayVerifier, "replayVerifier");
    }

    @Override
    public FormulaResultMaterializationResult materialize(String inputSnapshotSha256)
            throws IOException {
        String snapshotSha = requireSha(inputSnapshotSha256);
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

        RbvmResolvedDecisionInput resolved = evidenceResolver.resolve(snapshot);
        RbvmFormulaV1.FormulaResult formulaResult = RbvmFormulaV1.evaluate(resolved);
        RbvmFormulaV1Explanation explanation = RbvmFormulaV1Explanation.from(
                resolved,
                formulaResult
        );
        if (!snapshotSha.equals(explanation.inputSnapshotSha256())) {
            throw new IOException(
                    "Formula explanation does not match the requested Decision Input snapshot"
            );
        }

        FormulaResultInstallResult installResult = results.install(explanation);
        if (installResult.status() == FormulaResultInstallResult.Status.RESULT_CONFLICT) {
            throw new ResultConflictException(
                    snapshotSha,
                    explanation.canonicalSha256(),
                    installResult.existingExplanationSha256()
            );
        }
        if (!installResult.installedOrReplayed()) {
            throw new IOException("Formula result install returned an unsupported materialization state");
        }

        StoredFormulaResult stored = results
                .findByExplanationSha256(explanation.canonicalSha256())
                .orElseThrow(() -> new IOException(
                        "Formula materialization installed a result that cannot be reloaded by exact identity"
                ));
        RbvmFormulaV1Explanation replayed = replayVerifier.replay(stored);
        if (!explanation.canonicalSha256().equals(replayed.canonicalSha256())) {
            throw new IOException(
                    "Formula materialization replay produced a different canonical explanation identity"
            );
        }
        return new FormulaResultMaterializationResult(explanation, installResult, stored);
    }

    private static String requireSha(String value) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(
                    "inputSnapshotSha256 must be a lowercase SHA-256"
            );
        }
        return value;
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
            super("Formula V1 materialization requires RBVM_DECISION_INPUT_SNAPSHOT_V3");
            this.contractId = Objects.requireNonNull(contractId, "contractId");
        }

        public String contractId() {
            return contractId;
        }
    }

    public static final class ResultConflictException extends IOException {
        private static final long serialVersionUID = 1L;
        private final String inputSnapshotSha256;
        private final String requestedExplanationSha256;
        private final String existingExplanationSha256;

        ResultConflictException(
                String inputSnapshotSha256,
                String requestedExplanationSha256,
                String existingExplanationSha256
        ) {
            super("Persisted Formula result conflicts with deterministic materialization output");
            this.inputSnapshotSha256 = inputSnapshotSha256;
            this.requestedExplanationSha256 = requestedExplanationSha256;
            this.existingExplanationSha256 = existingExplanationSha256;
        }

        public String inputSnapshotSha256() {
            return inputSnapshotSha256;
        }

        public String requestedExplanationSha256() {
            return requestedExplanationSha256;
        }

        public String existingExplanationSha256() {
            return existingExplanationSha256;
        }
    }
}
