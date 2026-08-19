package io.rbvm.csv;

import java.util.Objects;

/** One explicit snapshot-bound row from CISA_KEV_CSV_V1. */
public record CisaKevCsvEvidence(
        long sourceRowNumber,
        CisaKevEvidence evidence
) {
    public CisaKevCsvEvidence {
        if (sourceRowNumber < 2) {
            throw new IllegalArgumentException("sourceRowNumber must be at least 2");
        }
        Objects.requireNonNull(evidence, "evidence");
        if (!evidence.hasCatalogEvidence()) {
            throw new IllegalArgumentException(
                    "CISA_KEV_CSV_V1 rows must be LISTED or NOT_LISTED snapshot evidence"
            );
        }
    }

    public String evidenceKey() {
        CisaKevCatalogSnapshot snapshot = evidence.snapshot();
        return evidence.cveId() + "\u001F"
                + snapshot.source() + "\u001F"
                + snapshot.observedAt();
    }

    public String normalizedContentKey() {
        CisaKevCatalogSnapshot snapshot = evidence.snapshot();
        return evidence.status().name() + "\u001F"
                + snapshot.catalogVersion() + "\u001F"
                + snapshot.sha256() + "\u001F"
                + snapshot.parsedCount() + "\u001F"
                + nullable(evidence.dateAdded()) + "\u001F"
                + nullable(evidence.dueDate()) + "\u001F"
                + nullable(evidence.ransomwareCampaignUse());
    }

    private static String nullable(Object value) {
        return value == null ? "" : value.toString();
    }
}
