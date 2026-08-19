package io.rbvm.csv;

import java.util.Objects;

/** One explicit FIRST EPSS score row from EPSS_CSV_V1. */
public record EpssCsvEvidence(
        long sourceRowNumber,
        EpssEvidence evidence
) {
    public EpssCsvEvidence {
        if (sourceRowNumber < 2) {
            throw new IllegalArgumentException("sourceRowNumber must be at least 2");
        }
        Objects.requireNonNull(evidence, "evidence");
    }

    public String evidenceKey() {
        return evidence.cveId() + "\u001F"
                + evidence.source() + "\u001F"
                + evidence.observedAt();
    }

    public String normalizedContentKey() {
        return evidence.probability().toPlainString() + "\u001F"
                + evidence.percentile().toPlainString() + "\u001F"
                + evidence.modelVersion() + "\u001F"
                + evidence.scoreDate() + "\u001F"
                + evidence.sourceSha256();
    }
}
