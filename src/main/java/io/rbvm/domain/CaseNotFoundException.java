package io.rbvm.domain;

public final class CaseNotFoundException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    public CaseNotFoundException(String caseId) {
        super("Vulnerability case was not found: " + caseId);
    }
}
