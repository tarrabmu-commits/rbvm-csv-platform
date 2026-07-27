package io.rbvm.domain;

public record PreparedCaseAction(CaseAuditEvent event, boolean replayed) {
}
