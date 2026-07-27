package io.rbvm.csv;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Objects;
import java.util.UUID;

/**
 * Minimal domain aggregate for the first CSV import vertical slice.
 * Persistence and HTTP adapters are deliberately outside this class.
 */
public final class CsvImportRun {
    private final UUID importId;
    private final String tenantId;
    private final String sourceProfileId;
    private final String fileSha256;
    private final Instant createdAt;
    private CsvImportStatus status;
    private AnalysisReport analysisReport;
    private String terminalReason;

    private CsvImportRun(
            UUID importId,
            String tenantId,
            String sourceProfileId,
            String fileSha256,
            Instant createdAt
    ) {
        this.importId = Objects.requireNonNull(importId, "importId");
        this.tenantId = requireText(tenantId, "tenantId");
        this.sourceProfileId = requireText(sourceProfileId, "sourceProfileId");
        this.fileSha256 = requireText(fileSha256, "fileSha256");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt");
        this.status = CsvImportStatus.UPLOADED;
    }

    public static CsvImportRun uploaded(
            UUID importId,
            String tenantId,
            String sourceProfileId,
            String fileSha256,
            Instant createdAt
    ) {
        return new CsvImportRun(importId, tenantId, sourceProfileId, fileSha256, createdAt);
    }

    public void startValidation() {
        transition(EnumSet.of(CsvImportStatus.UPLOADED), CsvImportStatus.VALIDATING);
    }

    public void previewReady(AnalysisReport report) {
        transition(EnumSet.of(CsvImportStatus.VALIDATING), CsvImportStatus.PREVIEW_READY);
        this.analysisReport = Objects.requireNonNull(report, "report");
    }

    public void startImport() {
        if (analysisReport == null) {
            throw new IllegalStateException("An analysis report is required before import");
        }
        transition(EnumSet.of(CsvImportStatus.PREVIEW_READY), CsvImportStatus.IMPORTING);
    }

    public void startReconciliation() {
        transition(EnumSet.of(CsvImportStatus.IMPORTING), CsvImportStatus.RECONCILING);
    }

    public void complete() {
        transition(EnumSet.of(CsvImportStatus.RECONCILING), CsvImportStatus.COMPLETED);
    }

    public void partial(String reason) {
        transition(EnumSet.of(CsvImportStatus.IMPORTING, CsvImportStatus.RECONCILING), CsvImportStatus.PARTIAL);
        this.terminalReason = requireText(reason, "reason");
    }

    public void reject(String reason) {
        transition(EnumSet.of(CsvImportStatus.UPLOADED, CsvImportStatus.VALIDATING), CsvImportStatus.REJECTED);
        this.terminalReason = requireText(reason, "reason");
    }

    public void fail(String reason) {
        if (status.terminal()) {
            throw new IllegalStateException("A terminal import cannot fail again: " + status);
        }
        this.status = CsvImportStatus.FAILED;
        this.terminalReason = requireText(reason, "reason");
    }

    private void transition(EnumSet<CsvImportStatus> allowed, CsvImportStatus target) {
        if (!allowed.contains(status)) {
            throw new IllegalStateException("Invalid CSV import transition: " + status + " -> " + target);
        }
        this.status = target;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }

    public UUID importId() {
        return importId;
    }

    public String tenantId() {
        return tenantId;
    }

    public String sourceProfileId() {
        return sourceProfileId;
    }

    public String fileSha256() {
        return fileSha256;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public CsvImportStatus status() {
        return status;
    }

    public AnalysisReport analysisReport() {
        return analysisReport;
    }

    public String terminalReason() {
        return terminalReason;
    }
}

