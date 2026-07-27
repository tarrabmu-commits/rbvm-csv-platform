package io.rbvm.domain;

public final class StaleCaseCursorException extends IllegalStateException {
    private static final long serialVersionUID = 1L;

    public StaleCaseCursorException(String message) {
        super(message);
    }
}
