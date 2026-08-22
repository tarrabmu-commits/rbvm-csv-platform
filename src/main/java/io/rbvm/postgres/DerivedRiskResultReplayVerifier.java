package io.rbvm.postgres;

import io.rbvm.decision.DecisionInputEvidenceResolver;
import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDerivedRiskCanonicalResult;
import io.rbvm.decision.RbvmDerivedRiskMethodology;
import io.rbvm.decision.RbvmDerivedRiskMethodologyCatalog;
import io.rbvm.decision.RbvmResolvedDecisionInput;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

/** Replays one persisted derived-risk result only from exact immutable Decision Input V3 provenance. */
public final class DerivedRiskResultReplayVerifier {
    private final DerivedRiskResultStore results;
    private final DecisionInputSnapshotStore decisionInputs;
    private final DecisionInputEvidenceResolver evidenceResolver;

    public DerivedRiskResultReplayVerifier(
            DerivedRiskResultStore results,
            DecisionInputSnapshotStore decisionInputs,
            DecisionInputEvidenceResolver evidenceResolver
    ) {
        this.results = Objects.requireNonNull(results, "results");
        this.decisionInputs = Objects.requireNonNull(decisionInputs, "decisionInputs");
        this.evidenceResolver = Objects.requireNonNull(evidenceResolver, "evidenceResolver");
    }

    public StoredDerivedRiskResult verifyByResultSha256(String resultSha256) throws IOException {
        StoredDerivedRiskResult stored = results.findByResultSha256(resultSha256)
                .orElseThrow(() -> new IOException(
                        "Persisted derived risk result does not exist for canonical identity"
                ));
        replay(stored);
        return stored;
    }

    public StoredDerivedRiskResult verifyBySnapshotAndMethodology(
            String inputSnapshotSha256,
            String methodologyId,
            String methodologySha256
    ) throws IOException {
        StoredDerivedRiskResult stored = results.findBySnapshotAndMethodology(
                        inputSnapshotSha256,
                        methodologyId,
                        methodologySha256
                )
                .orElseThrow(() -> new IOException(
                        "Persisted derived risk result does not exist for input/methodology identity"
                ));
        replay(stored);
        return stored;
    }

    /** Re-evaluates the exact stored methodology and requires byte-identical canonical result bytes. */
    public RbvmDerivedRiskCanonicalResult replay(StoredDerivedRiskResult stored) throws IOException {
        Objects.requireNonNull(stored, "stored");
        RbvmDecisionInputSnapshot snapshot = decisionInputs
                .findBySha256(stored.inputSnapshotSha256())
                .orElseThrow(() -> new IOException(
                        "Derived risk replay cannot resolve the persisted Decision Input snapshot"
                ));
        if (!snapshot.isV3()) {
            throw new IOException("Derived risk replay requires Decision Input Snapshot V3");
        }
        if (!stored.findingId().equals(snapshot.findingId())) {
            throw new IOException(
                    "Persisted derived risk result does not match its Decision Input Finding identity"
            );
        }

        RbvmDerivedRiskMethodology methodology = RbvmDerivedRiskMethodologyCatalog
                .find(stored.methodologyId())
                .orElseThrow(() -> new IOException(
                        "Persisted derived risk methodology implementation is unavailable"
                ));
        RbvmDerivedRiskMethodology.Definition definition = methodology.definition();
        if (definition.version() != stored.methodologyVersion()
                || !definition.methodologySha256().equals(stored.methodologySha256())) {
            throw new IOException(
                    "Persisted derived risk methodology identity does not match implementation"
            );
        }

        RbvmResolvedDecisionInput resolved = evidenceResolver.resolve(snapshot);
        RbvmDerivedRiskCanonicalResult replayed = RbvmDerivedRiskCanonicalResult.from(
                methodology.evaluate(resolved)
        );
        RbvmDerivedRiskMethodology.Evaluation evaluation = replayed.evaluation();

        if (!stored.inputSnapshotSha256().equals(evaluation.inputSnapshotSha256())
                || !stored.findingId().equals(evaluation.findingId())
                || !stored.methodologyId().equals(definition.methodologyId())
                || stored.methodologyVersion() != definition.version()
                || !stored.methodologySha256().equals(definition.methodologySha256())
                || stored.resultState() != evaluation.state()
                || !Objects.equals(stored.reasonCode(), evaluation.reasonCode())
                || !Objects.equals(stored.numericScore(), evaluation.numericScore())
                || !Objects.equals(stored.numericScale(), evaluation.numericScale())
                || !Objects.equals(stored.rating(), evaluation.rating())
                || !stored.canonicalPayloadFormat().equals(
                        RbvmDerivedRiskCanonicalResult.PAYLOAD_FORMAT
                )
                || !stored.resultSha256().equals(replayed.canonicalSha256())
                || !Arrays.equals(stored.canonicalPayload(), replayed.canonicalPayload())) {
            throw new IOException(
                    "Persisted derived risk result failed deterministic historical replay verification"
            );
        }
        return replayed;
    }

    public void verify(StoredDerivedRiskResult stored) throws IOException {
        replay(stored);
    }
}
