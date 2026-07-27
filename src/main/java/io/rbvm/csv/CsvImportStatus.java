package io.rbvm.csv;

public enum CsvImportStatus {
    UPLOADED,
    VALIDATING,
    PREVIEW_READY,
    IMPORTING,
    RECONCILING,
    COMPLETED,
    PARTIAL,
    REJECTED,
    FAILED;

    public boolean terminal() {
        return this == COMPLETED || this == PARTIAL || this == REJECTED || this == FAILED;
    }
}

