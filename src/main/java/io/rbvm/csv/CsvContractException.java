package io.rbvm.csv;

public final class CsvContractException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public CsvContractException(String message) {
        super(message);
    }

    public CsvContractException(String message, Throwable cause) {
        super(message, cause);
    }
}
