package io.rbvm.context;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

/**
 * One immutable customer-confirmed event associating a canonical Finding with one network
 * reachability scope. Missing history means never assessed; UNLINKED is an explicit customer
 * decision that the scope must not be applied to the Finding.
 *
 * <p>The target is a stable reachability scope, not one evidence row. This lets later evidence
 * refreshes reuse the explicit association while preserving exact evidence and exact association
 * provenance in a Decision Input snapshot.</p>
 */
public record FindingReachabilityScopeLink(
        UUID eventId,
        UUID findingId,
        int revision,
        LinkStatus linkStatus,
        OriginScope originScope,
        String originLabel,
        TransportProtocol transportProtocol,
        Integer targetPort,
        LinkMethod linkMethod,
        String evidenceSha256,
        String changedBy,
        String changeNote,
        Instant recordedAt
) {
    public static final String CONTRACT_ID = "FINDING_REACHABILITY_SCOPE_LINK_V1";

    public FindingReachabilityScopeLink {
        eventId = Objects.requireNonNull(eventId, "eventId");
        findingId = Objects.requireNonNull(findingId, "findingId");
        if (revision < 1) {
            throw new IllegalArgumentException("revision must be positive");
        }
        linkStatus = Objects.requireNonNull(linkStatus, "linkStatus");
        originScope = Objects.requireNonNull(originScope, "originScope");
        originLabel = normalizeKey(originLabel, "originLabel", 256);
        transportProtocol = Objects.requireNonNull(transportProtocol, "transportProtocol");
        validatePort(transportProtocol, targetPort);
        linkMethod = Objects.requireNonNull(linkMethod, "linkMethod");
        evidenceSha256 = requireSha256(evidenceSha256);
        changedBy = requireText(changedBy, "changedBy", 256);
        changeNote = Objects.requireNonNull(changeNote, "changeNote");
        recordedAt = Objects.requireNonNull(recordedAt, "recordedAt");
    }

    public String scopeKey() {
        return originScope.name() + "|"
                + originLabel.length() + ":" + originLabel + "|"
                + transportProtocol.name() + "|"
                + (targetPort == null ? "" : targetPort);
    }

    public boolean sameCustomerState(ChangeDraft draft) {
        Objects.requireNonNull(draft, "draft");
        return linkStatus == draft.linkStatus()
                && originScope == draft.originScope()
                && originLabel.equals(draft.originLabel())
                && transportProtocol == draft.transportProtocol()
                && Objects.equals(targetPort, draft.targetPort());
    }

    public static String evidenceSha256(
            UUID findingId,
            int revision,
            LinkStatus linkStatus,
            OriginScope originScope,
            String originLabel,
            TransportProtocol transportProtocol,
            Integer targetPort
    ) {
        Objects.requireNonNull(findingId, "findingId");
        if (revision < 1) {
            throw new IllegalArgumentException("revision must be positive");
        }
        Objects.requireNonNull(linkStatus, "linkStatus");
        Objects.requireNonNull(originScope, "originScope");
        String normalizedLabel = normalizeKey(originLabel, "originLabel", 256);
        Objects.requireNonNull(transportProtocol, "transportProtocol");
        validatePort(transportProtocol, targetPort);
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                writeString(output, CONTRACT_ID);
                output.writeLong(findingId.getMostSignificantBits());
                output.writeLong(findingId.getLeastSignificantBits());
                output.writeInt(revision);
                writeString(output, linkStatus.name());
                writeString(output, originScope.name());
                writeString(output, normalizedLabel);
                writeString(output, transportProtocol.name());
                output.writeBoolean(targetPort != null);
                if (targetPort != null) {
                    output.writeInt(targetPort);
                }
                writeString(output, LinkMethod.CUSTOMER_CONFIRMED.name());
            }
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(buffer.toByteArray()));
        } catch (IOException exception) {
            throw new IllegalStateException("Unexpected in-memory association hash failure", exception);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static void validatePort(TransportProtocol protocol, Integer targetPort) {
        if (targetPort != null && (targetPort < 1 || targetPort > 65_535)) {
            throw new IllegalArgumentException("targetPort must be between 1 and 65535 when present");
        }
        if ((protocol == TransportProtocol.TCP || protocol == TransportProtocol.UDP)
                && targetPort == null) {
            throw new IllegalArgumentException("targetPort is required for TCP or UDP scope");
        }
        if (protocol == TransportProtocol.ICMP && targetPort != null) {
            throw new IllegalArgumentException("targetPort must be absent for ICMP scope");
        }
    }

    private static String normalizeKey(String value, String field, int maximumLength) {
        String normalized = requireText(value, field, maximumLength);
        return Normalizer.normalize(normalized, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }

    private static String requireText(String value, String field, int maximumLength) {
        Objects.requireNonNull(value, field);
        String normalized = value.trim();
        if (normalized.isEmpty() || normalized.length() > maximumLength
                || normalized.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " is blank, invalid, or too long");
        }
        return normalized;
    }

    private static String requireSha256(String value) {
        Objects.requireNonNull(value, "evidenceSha256");
        if (!value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("evidenceSha256 must be lowercase SHA-256");
        }
        return value;
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(encoded.length);
        output.write(encoded);
    }

    public enum LinkStatus {
        LINKED,
        UNLINKED
    }

    public enum LinkMethod {
        CUSTOMER_CONFIRMED
    }

    public enum OriginScope {
        INTERNET,
        EXTERNAL_PARTNER,
        INTERNAL_ENTERPRISE,
        LOCAL_SEGMENT,
        OTHER,
        UNKNOWN
    }

    public enum TransportProtocol {
        TCP,
        UDP,
        ICMP,
        OTHER,
        UNKNOWN
    }

    /** Customer state plus authenticated audit metadata. Audit metadata is not association state. */
    public record ChangeDraft(
            LinkStatus linkStatus,
            OriginScope originScope,
            String originLabel,
            TransportProtocol transportProtocol,
            Integer targetPort,
            String changedBy,
            String changeNote
    ) {
        public ChangeDraft {
            linkStatus = Objects.requireNonNull(linkStatus, "linkStatus");
            originScope = Objects.requireNonNull(originScope, "originScope");
            originLabel = normalizeKey(originLabel, "originLabel", 256);
            transportProtocol = Objects.requireNonNull(transportProtocol, "transportProtocol");
            validatePort(transportProtocol, targetPort);
            changedBy = requireText(changedBy, "changedBy", 256);
            changeNote = Objects.requireNonNull(changeNote, "changeNote");
        }

        public static ChangeDraft linked(
                OriginScope originScope,
                String originLabel,
                TransportProtocol transportProtocol,
                Integer targetPort,
                String changedBy,
                String changeNote
        ) {
            return new ChangeDraft(
                    LinkStatus.LINKED,
                    originScope,
                    originLabel,
                    transportProtocol,
                    targetPort,
                    changedBy,
                    changeNote
            );
        }

        public static ChangeDraft unlinked(
                OriginScope originScope,
                String originLabel,
                TransportProtocol transportProtocol,
                Integer targetPort,
                String changedBy,
                String changeNote
        ) {
            return new ChangeDraft(
                    LinkStatus.UNLINKED,
                    originScope,
                    originLabel,
                    transportProtocol,
                    targetPort,
                    changedBy,
                    changeNote
            );
        }
    }
}
