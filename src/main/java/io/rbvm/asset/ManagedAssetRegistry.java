package io.rbvm.asset;

import io.rbvm.asset.ManagedAsset.RevisionDraft;

import java.io.IOException;
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

    enum MutationStatus {
        CREATED,
        UPDATED,
        REPLAYED,
        NOT_FOUND,
        ASSET_ID_CONFLICT,
        CUSTOMER_KEY_CONFLICT,
        REVISION_CONFLICT
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
