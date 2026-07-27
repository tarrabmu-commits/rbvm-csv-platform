package io.rbvm.domain;

import java.time.Instant;
import java.util.Objects;

public record CaseActionCommand(
        CaseActionType action,
        String reason,
        Instant expiresAt,
        String evidenceReference
) {
    public CaseActionCommand {
        Objects.requireNonNull(action, "action");
        reason = requireText(reason, "reason", 2_000);
        evidenceReference = optionalText(evidenceReference, "evidenceReference", 1_000);

        if (action == CaseActionType.ACCEPT_RISK && expiresAt == null) {
            throw new InvalidCaseActionException("ACCEPT_RISK requires expiresAt");
        }
        if (action != CaseActionType.ACCEPT_RISK && expiresAt != null) {
            throw new InvalidCaseActionException(action + " does not accept expiresAt");
        }
        if (action == CaseActionType.CLOSE_MANUAL && evidenceReference == null) {
            throw new InvalidCaseActionException("CLOSE_MANUAL requires evidenceReference");
        }
    }

    private static String requireText(String value, String field, int maximum) {
        if (value == null || value.isBlank()) {
            throw new InvalidCaseActionException(field + " is required");
        }
        String trimmed = value.trim();
        if (trimmed.length() > maximum) {
            throw new InvalidCaseActionException(field + " must not exceed " + maximum + " characters");
        }
        return trimmed;
    }

    private static String optionalText(String value, String field, int maximum) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return requireText(value, field, maximum);
    }
}
