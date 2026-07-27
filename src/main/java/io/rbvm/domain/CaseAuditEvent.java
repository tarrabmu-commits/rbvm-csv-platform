package io.rbvm.domain;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

public record CaseAuditEvent(
        long sequence,
        String eventId,
        String caseId,
        long caseVersion,
        String idempotencyKey,
        String requestFingerprint,
        CaseActionType action,
        CaseStatus fromStatus,
        CaseStatus toStatus,
        String reason,
        Instant expiresAt,
        String evidenceReference,
        String actorId,
        String actorAssurance,
        Instant occurredAt
) {
    public CaseAuditEvent {
        if (sequence < 1 || caseVersion < 1) {
            throw new IllegalArgumentException("sequence and caseVersion must be positive");
        }
        requireHash(eventId, "eventId");
        requireHash(caseId, "caseId");
        requireHash(requestFingerprint, "requestFingerprint");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(fromStatus, "fromStatus");
        Objects.requireNonNull(toStatus, "toStatus");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(actorId, "actorId");
        Objects.requireNonNull(actorAssurance, "actorAssurance");
        Objects.requireNonNull(occurredAt, "occurredAt");
    }

    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("sequence", sequence);
        output.put("eventId", eventId);
        output.put("caseId", caseId);
        output.put("caseVersion", caseVersion);
        output.put("action", action.name());
        output.put("fromStatus", fromStatus.name());
        output.put("toStatus", toStatus.name());
        output.put("reason", reason);
        output.put("expiresAt", expiresAt == null ? null : expiresAt.toString());
        output.put("evidenceReference", evidenceReference);
        output.put("actorId", actorId);
        output.put("actorAssurance", actorAssurance);
        output.put("occurredAt", occurredAt.toString());
        return output;
    }

    public Properties toProperties() {
        Properties output = new Properties();
        output.setProperty("sequence", Long.toString(sequence));
        output.setProperty("eventId", eventId);
        output.setProperty("caseId", caseId);
        output.setProperty("caseVersion", Long.toString(caseVersion));
        output.setProperty("idempotencyKey", idempotencyKey);
        output.setProperty("requestFingerprint", requestFingerprint);
        output.setProperty("action", action.name());
        output.setProperty("fromStatus", fromStatus.name());
        output.setProperty("toStatus", toStatus.name());
        output.setProperty("reason", reason);
        if (expiresAt != null) {
            output.setProperty("expiresAt", expiresAt.toString());
        }
        if (evidenceReference != null) {
            output.setProperty("evidenceReference", evidenceReference);
        }
        output.setProperty("actorId", actorId);
        output.setProperty("actorAssurance", actorAssurance);
        output.setProperty("occurredAt", occurredAt.toString());
        return output;
    }

    public static CaseAuditEvent fromProperties(Properties input) {
        return new CaseAuditEvent(
                Long.parseLong(required(input, "sequence")),
                required(input, "eventId"),
                required(input, "caseId"),
                Long.parseLong(required(input, "caseVersion")),
                required(input, "idempotencyKey"),
                required(input, "requestFingerprint"),
                CaseActionType.valueOf(required(input, "action")),
                CaseStatus.valueOf(required(input, "fromStatus")),
                CaseStatus.valueOf(required(input, "toStatus")),
                required(input, "reason"),
                optionalInstant(input.getProperty("expiresAt")),
                optional(input.getProperty("evidenceReference")),
                required(input, "actorId"),
                required(input, "actorAssurance"),
                Instant.parse(required(input, "occurredAt"))
        );
    }

    private static String required(Properties input, String key) {
        String value = input.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing case event property: " + key);
        }
        return value;
    }

    private static String optional(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static Instant optionalInstant(String value) {
        return value == null || value.isBlank() ? null : Instant.parse(value);
    }

    private static void requireHash(String value, String field) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be a lowercase SHA-256 value");
        }
    }
}
