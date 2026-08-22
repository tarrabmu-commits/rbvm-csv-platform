package io.rbvm.postgres;

import io.rbvm.decision.DecisionInputEvidenceResolver;
import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmFormulaV1Explanation;
import io.rbvm.decision.RbvmResolvedDecisionInput;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

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

    public FormulaResultReplayVerifier(
            FormulaResultStore formulaResults,
            DecisionInputSnapshotStore decisionInputs,
            DecisionInputEvidenceResolver evidenceResolver
    ) {
        this.formulaResults = Objects.requireNonNull(formulaResults, "formulaResults");
        this.decisionInputs = Objects.requireNonNull(decisionInputs, "decisionInputs");
        this.evidenceResolver = Objects.requireNonNull(evidenceResolver, "evidenceResolver");
    }

    public StoredFormulaResult verifyByExplanationSha256(String explanationSha256)
            throws IOException {
        StoredFormulaResult stored = formulaResults
                .findByExplanationSha256(explanationSha256)
                .orElseThrow(() -> new IOException(
                        "Persisted Formula result does not exist for explanation identity"
                ));
        verify(stored);
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
        verify(stored);
        return stored;
    }

    public void verify(StoredFormulaResult stored) throws IOException {
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
