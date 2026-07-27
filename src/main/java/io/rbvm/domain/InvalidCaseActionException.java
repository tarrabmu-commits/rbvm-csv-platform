package io.rbvm.domain;

public final class InvalidCaseActionException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    public InvalidCaseActionException(String message) {
        super(message);
    }
}
