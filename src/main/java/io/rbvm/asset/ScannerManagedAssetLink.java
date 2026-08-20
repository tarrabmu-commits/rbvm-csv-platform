package io.rbvm.asset;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

/**
 * One immutable event in the explicit scanner-asset to customer-managed-asset link stream.
 * Missing history means never linked; an UNLINKED event means explicitly unlinked.
 */
public record ScannerManagedAssetLink(
        UUID eventId,
        UUID scannerAssetId,
        int revision,
        LinkStatus linkStatus,
        UUID managedAssetId,
        LinkMethod linkMethod,
        String evidenceSha256,
        String changedBy,
        String changeNote,
        Instant recordedAt
) {
    public static final String CONTRACT_ID = "SCANNER_MANAGED_ASSET_LINK_V1";

    public ScannerManagedAssetLink {
        Objects.requireNonNull(eventId, "eventId");
        Objects.requireNonNull(scannerAssetId, "scannerAssetId");
        Objects.requireNonNull(linkStatus, "linkStatus");
        Objects.requireNonNull(linkMethod, "linkMethod");
        Objects.requireNonNull(recordedAt, "recordedAt");
        if (revision < 1) {
            throw new IllegalArgumentException("revision must be positive");
        }
        validateState(linkStatus, managedAssetId);
        evidenceSha256 = requireSha256(evidenceSha256);
        changedBy = requireText(changedBy, "changedBy");
        changeNote = Objects.requireNonNull(changeNote, "changeNote");
    }

    public boolean sameCustomerState(ChangeDraft draft) {
        Objects.requireNonNull(draft, "draft");
        return linkStatus == draft.linkStatus()
                && Objects.equals(managedAssetId, draft.managedAssetId());
    }

    public static String evidenceSha256(
            UUID scannerAssetId,
            int revision,
            LinkStatus linkStatus,
            UUID managedAssetId
    ) {
        Objects.requireNonNull(scannerAssetId, "scannerAssetId");
        Objects.requireNonNull(linkStatus, "linkStatus");
        if (revision < 1) {
            throw new IllegalArgumentException("revision must be positive");
        }
        validateState(linkStatus, managedAssetId);
        String payload = CONTRACT_ID + "\n"
                + "scannerAssetId=" + scannerAssetId + "\n"
                + "revision=" + revision + "\n"
                + "linkStatus=" + linkStatus + "\n"
                + "managedAssetId=" + (managedAssetId == null ? "" : managedAssetId) + "\n"
                + "linkMethod=" + LinkMethod.CUSTOMER_CONFIRMED + "\n";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static void validateState(LinkStatus status, UUID managedAssetId) {
        if (status == LinkStatus.LINKED && managedAssetId == null) {
            throw new IllegalArgumentException("LINKED requires managedAssetId");
        }
        if (status == LinkStatus.UNLINKED && managedAssetId != null) {
            throw new IllegalArgumentException("UNLINKED must not contain managedAssetId");
        }
    }

    private static String requireSha256(String value) {
        Objects.requireNonNull(value, "evidenceSha256");
        if (!value.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("evidenceSha256 must be lowercase SHA-256");
        }
        return value;
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        String normalized = value.trim();
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return normalized;
    }

    public enum LinkStatus {
        LINKED,
        UNLINKED
    }

    public enum LinkMethod {
        CUSTOMER_CONFIRMED
    }

    /** Customer state plus authenticated audit metadata. Audit metadata is not link state. */
    public record ChangeDraft(
            LinkStatus linkStatus,
            UUID managedAssetId,
            String changedBy,
            String changeNote
    ) {
        public ChangeDraft {
            Objects.requireNonNull(linkStatus, "linkStatus");
            validateState(linkStatus, managedAssetId);
            changedBy = requireText(changedBy, "changedBy");
            changeNote = Objects.requireNonNull(changeNote, "changeNote");
        }

        public static ChangeDraft linked(UUID managedAssetId, String changedBy, String changeNote) {
            return new ChangeDraft(LinkStatus.LINKED, managedAssetId, changedBy, changeNote);
        }

        public static ChangeDraft unlinked(String changedBy, String changeNote) {
            return new ChangeDraft(LinkStatus.UNLINKED, null, changedBy, changeNote);
        }
    }
}
