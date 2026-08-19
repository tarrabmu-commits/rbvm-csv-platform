package io.rbvm.csv;

import java.util.Objects;

/** One explicit row from CVSS_V31_CSV_V1. */
public record CvssV31CsvEvidence(
        long sourceRowNumber,
        CvssV31BaseEvidence evidence
) {
    public CvssV31CsvEvidence {
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
        return evidence.version() + "\u001F"
                + evidence.baseScore().toPlainString() + "\u001F"
                + evidence.canonicalVector();
    }
}
