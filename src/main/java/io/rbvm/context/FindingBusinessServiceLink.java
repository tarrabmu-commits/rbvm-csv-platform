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
 * One immutable customer-confirmed event associating a canonical Finding with one normalized
 * business-service scope. Missing history means never assessed; UNLINKED is an explicit customer
 * decision that the service-scoped Business Impact evidence must not be applied to the Finding.
 */
public record FindingBusinessServiceLink(
        UUID eventId,
        UUID findingId,
        int revision,
        LinkStatus linkStatus,
        String businessService,
        LinkMethod linkMethod,
        String evidenceSha256,
        String changedBy,
        String changeNote,
        Instant recordedAt
) {
    public static final String CONTRACT_ID = "FINDING_BUSINESS_SERVICE_LINK_V1";

    public FindingBusinessServiceLink {
        eventId = Objects.requireNonNull(eventId, "eventId");
        findingId = Objects.requireNonNull(findingId, "findingId");
        if (revision < 1) {
            throw new IllegalArgumentException("revision must be positive");
        }
        linkStatus = Objects.requireNonNull(linkStatus, "linkStatus");
        businessService = normalizeService(businessService);
        linkMethod = Objects.requireNonNull(linkMethod, "linkMethod");
        evidenceSha256 = requireSha256(evidenceSha256);
        changedBy = requireText(changedBy, "changedBy", 256);
        changeNote = Objects.requireNonNull(changeNote, "changeNote");
        recordedAt = Objects.requireNonNull(recordedAt, "recordedAt");
    }

    public boolean sameCustomerState(ChangeDraft draft) {
        Objects.requireNonNull(draft, "draft");
        return linkStatus == draft.linkStatus()
                && businessService.equals(draft.businessService());
    }

    public static String evidenceSha256(
            UUID findingId,
            int revision,
            LinkStatus linkStatus,
            String businessService
    ) {
        Objects.requireNonNull(findingId, "findingId");
        if (revision < 1) {
            throw new IllegalArgumentException("revision must be positive");
        }
        Objects.requireNonNull(linkStatus, "linkStatus");
        String normalizedService = normalizeService(businessService);
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                writeString(output, CONTRACT_ID);
                output.writeLong(findingId.getMostSignificantBits());
                output.writeLong(findingId.getLeastSignificantBits());
                output.writeInt(revision);
                writeString(output, linkStatus.name());
                writeString(output, normalizedService);
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

    private static String normalizeService(String value) {
        String normalized = requireText(value, "businessService", 256);
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

    /** Customer state plus authenticated audit metadata. Audit metadata is not association state. */
    public record ChangeDraft(
            LinkStatus linkStatus,
            String businessService,
            String changedBy,
            String changeNote
    ) {
        public ChangeDraft {
            linkStatus = Objects.requireNonNull(linkStatus, "linkStatus");
            businessService = normalizeService(businessService);
            changedBy = requireText(changedBy, "changedBy", 256);
            changeNote = Objects.requireNonNull(changeNote, "changeNote");
        }

        public static ChangeDraft linked(
                String businessService,
                String changedBy,
                String changeNote
        ) {
            return new ChangeDraft(
                    LinkStatus.LINKED,
                    businessService,
                    changedBy,
                    changeNote
            );
        }

        public static ChangeDraft unlinked(
                String businessService,
                String changedBy,
                String changeNote
        ) {
            return new ChangeDraft(
                    LinkStatus.UNLINKED,
                    businessService,
                    changedBy,
                    changeNote
            );
        }
    }
}
