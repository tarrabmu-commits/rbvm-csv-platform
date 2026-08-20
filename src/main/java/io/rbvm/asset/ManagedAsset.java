package io.rbvm.asset;

import io.rbvm.csv.AssetContextCsvEvidence.BusinessCriticality;
import io.rbvm.csv.AssetContextCsvEvidence.Environment;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/** Stable customer-owned asset identity with an append-only current revision. */
public record ManagedAsset(
        UUID id,
        String customerAssetKey,
        Instant createdAt,
        Revision currentRevision
) {
    public static final String CONTEXT_SOURCE = "CUSTOMER_ASSET_REGISTRY";
    private static final Pattern SHA256 = Pattern.compile("^[a-f0-9]{64}$");

    public ManagedAsset {
        Objects.requireNonNull(id, "id");
        customerAssetKey = optionalText(customerAssetKey);
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(currentRevision, "currentRevision");
        if (!currentRevision.managedAssetId().equals(id)) {
            throw new IllegalArgumentException("currentRevision must belong to managed asset");
        }
    }

    public enum LifecycleStatus {
        ACTIVE,
        RETIRED
    }

    public enum ClassificationMethod {
        CUSTOMER_DIRECT,
        GUIDED
    }

    /** Customer-selected state used when creating or appending a revision. */
    public record RevisionDraft(
            LifecycleStatus lifecycleStatus,
            String displayName,
            Environment environment,
            String businessService,
            String businessOwner,
            BusinessCriticality businessCriticality,
            ClassificationMethod classificationMethod,
            String guideContractId,
            Integer guideRevision,
            String changedBy,
            String changeNote
    ) {
        public RevisionDraft {
            Objects.requireNonNull(lifecycleStatus, "lifecycleStatus");
            displayName = requireText(displayName, "displayName");
            Objects.requireNonNull(environment, "environment");
            businessService = requireText(businessService, "businessService");
            businessOwner = requireText(businessOwner, "businessOwner");
            Objects.requireNonNull(businessCriticality, "businessCriticality");
            Objects.requireNonNull(classificationMethod, "classificationMethod");
            guideContractId = optionalText(guideContractId);
            changedBy = requireText(changedBy, "changedBy");
            changeNote = changeNote == null ? "" : changeNote.trim();
            validateGuideBasis(classificationMethod, guideContractId, guideRevision);
        }

        public boolean sameCustomerState(Revision revision) {
            Objects.requireNonNull(revision, "revision");
            return lifecycleStatus == revision.lifecycleStatus()
                    && displayName.equals(revision.displayName())
                    && environment == revision.environment()
                    && businessService.equals(revision.businessService())
                    && businessOwner.equals(revision.businessOwner())
                    && businessCriticality == revision.businessCriticality()
                    && classificationMethod == revision.classificationMethod()
                    && Objects.equals(guideContractId, revision.guideContractId())
                    && Objects.equals(guideRevision, revision.guideRevision());
        }
    }

    /** One immutable customer-context revision. */
    public record Revision(
            UUID id,
            UUID managedAssetId,
            int revision,
            LifecycleStatus lifecycleStatus,
            String displayName,
            Environment environment,
            String businessService,
            String businessOwner,
            BusinessCriticality businessCriticality,
            ClassificationMethod classificationMethod,
            String guideContractId,
            Integer guideRevision,
            String contextSource,
            String evidenceSha256,
            String changedBy,
            String changeNote,
            Instant recordedAt
    ) {
        public Revision {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(managedAssetId, "managedAssetId");
            if (revision < 1) {
                throw new IllegalArgumentException("revision must be positive");
            }
            Objects.requireNonNull(lifecycleStatus, "lifecycleStatus");
            displayName = requireText(displayName, "displayName");
            Objects.requireNonNull(environment, "environment");
            businessService = requireText(businessService, "businessService");
            businessOwner = requireText(businessOwner, "businessOwner");
            Objects.requireNonNull(businessCriticality, "businessCriticality");
            Objects.requireNonNull(classificationMethod, "classificationMethod");
            guideContractId = optionalText(guideContractId);
            validateGuideBasis(classificationMethod, guideContractId, guideRevision);
            contextSource = requireText(contextSource, "contextSource");
            if (!CONTEXT_SOURCE.equals(contextSource)) {
                throw new IllegalArgumentException("unsupported managed asset contextSource");
            }
            evidenceSha256 = requireText(evidenceSha256, "evidenceSha256");
            if (!SHA256.matcher(evidenceSha256).matches()) {
                throw new IllegalArgumentException("evidenceSha256 must be lowercase SHA-256 hex");
            }
            changedBy = requireText(changedBy, "changedBy");
            changeNote = changeNote == null ? "" : changeNote.trim();
            Objects.requireNonNull(recordedAt, "recordedAt");
        }
    }

    private static void validateGuideBasis(
            ClassificationMethod classificationMethod,
            String guideContractId,
            Integer guideRevision
    ) {
        if (classificationMethod == ClassificationMethod.CUSTOMER_DIRECT) {
            if (guideContractId != null || guideRevision != null) {
                throw new IllegalArgumentException(
                        "CUSTOMER_DIRECT classification must not claim a guide version");
            }
            return;
        }
        if (guideContractId == null || guideRevision == null || guideRevision < 1) {
            throw new IllegalArgumentException(
                    "GUIDED classification requires guideContractId and positive guideRevision");
        }
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }

    private static String optionalText(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
