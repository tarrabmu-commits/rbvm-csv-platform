package io.rbvm.domain;

public final class CaseWorkflowConflictException extends IllegalStateException {
    private static final long serialVersionUID = 1L;

    public CaseWorkflowConflictException(String message) {
        super(message);
    }
}
