package io.rbvm.postgres;

import io.rbvm.decision.DecisionInputEvidenceResolver;
import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmFormulaV1Explanation;
import io.rbvm.decision.RbvmResolvedDecisionInput;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Replays one persisted Formula result only from its immutable Decision Input V3 provenance.
 *
 * <p>The verifier never rebuilds a Decision Input snapshot, selects current evidence, or consults
 * current association state. It reloads the exact persisted snapshot, resolves only the native
 * evidence and binding references captured by that snapshot, re-runs Formula V1, and requires the
 * canonical explanation bytes to match the persisted bytes exactly.</p>
 */
public final class FormulaResultReplayVerifier {
    private final FormulaResultStore formulaResults;
    private final DecisionInputSnapshotStore decisionInputs;
    private final DecisionInputEvidenceResolver evidenceResolver;
    private final Optional<DecisionInputRuntimeAccess> decisionInputRuntime;

    public FormulaResultReplayVerifier(
            FormulaResultStore formulaResults,
            DecisionInputSnapshotStore decisionInputs,
            DecisionInputEvidenceResolver evidenceResolver
    ) {
        this(formulaResults, decisionInputs, evidenceResolver, Optional.empty());
    }

    public FormulaResultReplayVerifier(
            FormulaResultStore formulaResults,
            DecisionInputSnapshotStore decisionInputs,
            DecisionInputEvidenceResolver evidenceResolver,
            DecisionInputRuntimeAccess decisionInputRuntime
    ) {
        this(
                formulaResults,
                decisionInputs,
                evidenceResolver,
                Optional.of(Objects.requireNonNull(decisionInputRuntime, "decisionInputRuntime"))
        );
    }

    private FormulaResultReplayVerifier(
            FormulaResultStore formulaResults,
            DecisionInputSnapshotStore decisionInputs,
            DecisionInputEvidenceResolver evidenceResolver,
            Optional<DecisionInputRuntimeAccess> decisionInputRuntime
    ) {
        this.formulaResults = Objects.requireNonNull(formulaResults, "formulaResults");
        this.decisionInputs = Objects.requireNonNull(decisionInputs, "decisionInputs");
        this.evidenceResolver = Objects.requireNonNull(evidenceResolver, "evidenceResolver");
        this.decisionInputRuntime = Objects.requireNonNull(
                decisionInputRuntime,
                "decisionInputRuntime"
        );
    }

    public Optional<DecisionInputRuntimeAccess> decisionInputRuntime() {
        return decisionInputRuntime;
    }

    public StoredFormulaResult verifyByExplanationSha256(String explanationSha256)
            throws IOException {
        StoredFormulaResult stored = formulaResults
                .findByExplanationSha256(explanationSha256)
                .orElseThrow(() -> new IOException(
                        "Persisted Formula result does not exist for explanation identity"
                ));
        replay(stored);
        return stored;
    }

    public StoredFormulaResult verifyBySnapshotAndFormula(
            String inputSnapshotSha256,
            String formulaSha256
    ) throws IOException {
        StoredFormulaResult stored = formulaResults
                .findBySnapshotAndFormula(inputSnapshotSha256, formulaSha256)
                .orElseThrow(() -> new IOException(
                        "Persisted Formula result does not exist for input/formula identity"
                ));
        replay(stored);
        return stored;
    }

    /**
     * Materializes Formula V1 only from one exact already-persisted Decision Input V3 identity.
     *
     * <p>This convenience boundary deliberately reuses the same immutable stores, exact evidence
     * resolver, and replay verifier as read-time historical verification. It never invokes a
     * Decision Input builder or selects current evidence.</p>
     */
    public FormulaResultMaterializationResult materializeExactSnapshot(String inputSnapshotSha256)
            throws IOException {
        return new DefaultFormulaResultMaterializer(
                decisionInputs,
                evidenceResolver,
                formulaResults,
                this
        ).materialize(inputSnapshotSha256);
    }

    /**
     * Reconstructs the exact canonical explanation after proving it is byte-identical to storage.
     * This is the safe structured-explanation boundary for read APIs and audit tooling.
     */
    public RbvmFormulaV1Explanation replay(StoredFormulaResult stored) throws IOException {
        Objects.requireNonNull(stored, "stored");
        RbvmDecisionInputSnapshot snapshot = decisionInputs
                .findBySha256(stored.inputSnapshotSha256())
                .orElseThrow(() -> new IOException(
                        "Formula replay cannot resolve the persisted Decision Input snapshot"
                ));
        if (!snapshot.isV3()) {
            throw new IOException("Formula replay requires Decision Input Snapshot V3");
        }
        requireSnapshotIdentity(stored, snapshot);

        RbvmResolvedDecisionInput resolved = evidenceResolver.resolve(snapshot);
        RbvmFormulaV1.FormulaResult replayedResult = RbvmFormulaV1.evaluate(resolved);
        RbvmFormulaV1Explanation replayed = RbvmFormulaV1Explanation.from(
                resolved,
                replayedResult
        );

        if (!stored.formulaId().equals(replayed.formulaId())
                || stored.formulaVersion() != replayed.formulaVersion()
                || !stored.formulaSha256().equals(replayed.formulaSha256())
                || stored.resultState() != replayed.resultState()
                || !stored.reasonCodes().equals(replayed.reasonCodes())
                || !Objects.equals(stored.relativeRiskIndex(), replayed.finalRiskResult())
                || !stored.explanationPayloadFormat().equals(
                        RbvmFormulaV1Explanation.PAYLOAD_FORMAT
                )
                || !stored.explanationSha256().equals(replayed.canonicalSha256())
                || !Arrays.equals(stored.explanationPayload(), replayed.canonicalPayload())) {
            throw new IOException(
                    "Persisted Formula result failed deterministic historical replay verification"
            );
        }
        return replayed;
    }

    public void verify(StoredFormulaResult stored) throws IOException {
        replay(stored);
    }

    private static void requireSnapshotIdentity(
            StoredFormulaResult stored,
            RbvmDecisionInputSnapshot snapshot
    ) throws IOException {
        if (!stored.inputSnapshotSha256().equals(snapshot.snapshotSha256())
                || !stored.findingId().equals(snapshot.findingId())
                || !stored.evaluatedAt().equals(snapshot.evaluatedAt())
                || stored.methodologyRevision() != snapshot.methodologyRevision()
                || !stored.methodologyPolicySha256().equals(
                        snapshot.methodologyPolicySha256()
                )) {
            throw new IOException(
                    "Persisted Formula result does not match its Decision Input snapshot identity"
            );
        }
    }
}
