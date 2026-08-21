package io.rbvm.asset;

import io.rbvm.asset.ScannerManagedAssetLink.ChangeDraft;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Durable append-only registry for explicit scanner-asset to managed-asset decisions. */
public interface ScannerManagedAssetLinkRegistry {
    /**
     * Append the desired explicit state using optimistic revision control.
     * expectedRevision=0 means no link decision has ever been recorded for the scanner asset.
     */
    MutationResult revise(UUID scannerAssetId, int expectedRevision, ChangeDraft nextState)
            throws IOException;

    /** Distinguishes a missing scanner asset from an existing scanner asset with no link history. */
    CurrentLookup current(UUID scannerAssetId) throws IOException;

    /** Immutable newest-first event history. Empty optional means the scanner asset does not exist. */
    Optional<HistoryPage> history(UUID scannerAssetId, int limit, Integer beforeRevision)
            throws IOException;

    /** Tenant-scoped scanner identities with their latest explicit link decision, if one exists. */
    ScannerAssetPage list(int limit, UUID afterId) throws IOException;

    enum MutationStatus {
        UPDATED,
        REPLAYED,
        SCANNER_ASSET_NOT_FOUND,
        MANAGED_ASSET_NOT_FOUND,
        REVISION_CONFLICT
    }

    record CurrentLookup(boolean scannerAssetExists, ScannerManagedAssetLink current) {
        public CurrentLookup {
            if (!scannerAssetExists && current != null) {
                throw new IllegalArgumentException("missing scanner asset cannot have link state");
            }
        }

        public Optional<ScannerManagedAssetLink> currentOptional() {
            return Optional.ofNullable(current);
        }
    }

    record MutationResult(MutationStatus status, ScannerManagedAssetLink current) {
        public MutationResult {
            Objects.requireNonNull(status, "status");
            if ((status == MutationStatus.UPDATED || status == MutationStatus.REPLAYED)
                    && current == null) {
                throw new IllegalArgumentException(status + " requires current state");
            }
        }
    }

    record HistoryPage(
            UUID scannerAssetId,
            List<ScannerManagedAssetLink> events,
            Integer nextBeforeRevision
    ) {
        public HistoryPage {
            Objects.requireNonNull(scannerAssetId, "scannerAssetId");
            events = List.copyOf(Objects.requireNonNull(events, "events"));
            for (ScannerManagedAssetLink event : events) {
                if (!scannerAssetId.equals(event.scannerAssetId())) {
                    throw new IllegalArgumentException("history contains another scanner asset");
                }
            }
            if (nextBeforeRevision != null && nextBeforeRevision < 1) {
                throw new IllegalArgumentException("nextBeforeRevision must be positive");
            }
        }
    }

    record ScannerAssetSummary(
            UUID scannerAssetId,
            String observedName,
            String osNameRaw,
            String sourceProfileKey,
            String identityBasis,
            String identityConfidence,
            Instant firstObservedAt,
            Instant lastObservedAt,
            ScannerManagedAssetLink current
    ) {
        public ScannerAssetSummary {
            Objects.requireNonNull(scannerAssetId, "scannerAssetId");
            observedName = requireText(observedName, "observedName");
            osNameRaw = Objects.requireNonNull(osNameRaw, "osNameRaw");
            sourceProfileKey = requireText(sourceProfileKey, "sourceProfileKey");
            identityBasis = requireText(identityBasis, "identityBasis");
            identityConfidence = requireText(identityConfidence, "identityConfidence");
            Objects.requireNonNull(firstObservedAt, "firstObservedAt");
            Objects.requireNonNull(lastObservedAt, "lastObservedAt");
            if (firstObservedAt.isAfter(lastObservedAt)) {
                throw new IllegalArgumentException("firstObservedAt must not be after lastObservedAt");
            }
            if (current != null && !scannerAssetId.equals(current.scannerAssetId())) {
                throw new IllegalArgumentException("current link belongs to another scanner asset");
            }
        }
    }

    record ScannerAssetPage(List<ScannerAssetSummary> assets, UUID nextAfterId) {
        public ScannerAssetPage {
            assets = List.copyOf(Objects.requireNonNull(assets, "assets"));
        }
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        String normalized = value.trim();
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return normalized;
    }
}
