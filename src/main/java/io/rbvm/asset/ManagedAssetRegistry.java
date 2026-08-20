package io.rbvm.asset;

import io.rbvm.asset.ManagedAsset.Revision;
import io.rbvm.asset.ManagedAsset.RevisionDraft;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Durable customer-managed asset registry with optimistic revision control. */
public interface ManagedAssetRegistry {
    MutationResult create(UUID managedAssetId, String customerAssetKey, RevisionDraft initialRevision)
            throws IOException;

    MutationResult revise(UUID managedAssetId, int expectedRevision, RevisionDraft nextRevision)
            throws IOException;

    Optional<ManagedAsset> find(UUID managedAssetId) throws IOException;

    /** Deterministic current-state page ordered by managed-asset UUID. */
    ManagedAssetPage list(int limit, UUID afterId, LifecycleFilter lifecycleFilter)
            throws IOException;

    /** Immutable history page ordered from newest to oldest revision. */
    Optional<RevisionPage> history(UUID managedAssetId, int limit, Integer beforeRevision)
            throws IOException;

    enum LifecycleFilter {
        ALL,
        ACTIVE,
        RETIRED
    }

    enum MutationStatus {
        CREATED,
        UPDATED,
        REPLAYED,
        NOT_FOUND,
        ASSET_ID_CONFLICT,
        CUSTOMER_KEY_CONFLICT,
        REVISION_CONFLICT
    }

    record ManagedAssetPage(List<ManagedAsset> assets, UUID nextAfterId) {
        public ManagedAssetPage {
            assets = List.copyOf(Objects.requireNonNull(assets, "assets"));
        }
    }

    record RevisionPage(UUID managedAssetId, List<Revision> revisions, Integer nextBeforeRevision) {
        public RevisionPage {
            Objects.requireNonNull(managedAssetId, "managedAssetId");
            revisions = List.copyOf(Objects.requireNonNull(revisions, "revisions"));
            for (Revision revision : revisions) {
                if (!managedAssetId.equals(revision.managedAssetId())) {
                    throw new IllegalArgumentException("revision page contains another managed asset");
                }
            }
            if (nextBeforeRevision != null && nextBeforeRevision < 1) {
                throw new IllegalArgumentException("nextBeforeRevision must be positive");
            }
        }
    }

    record MutationResult(MutationStatus status, ManagedAsset asset) {
        public MutationResult {
            Objects.requireNonNull(status, "status");
            if (status == MutationStatus.NOT_FOUND) {
                if (asset != null) {
                    throw new IllegalArgumentException("NOT_FOUND must not contain an asset");
                }
            } else {
                Objects.requireNonNull(asset, "asset");
            }
        }
    }
}
