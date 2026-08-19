package io.rbvm.csv;

import java.text.Normalizer;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * One explicit, asset-scoped organizational context observation.
 *
 * <p>This evidence describes organizational context only. It does not encode network reachability,
 * exploitability, risk, priority, or treatment policy.</p>
 */
public record AssetContextCsvEvidence(
        long sourceRowNumber,
        String sourceProfileKey,
        AssetIdentityBasis assetIdentityBasis,
        String assetObservedName,
        String assetSourceId,
        Environment environment,
        String businessService,
        String businessOwner,
        BusinessCriticality businessCriticality,
        String contextSource,
        Instant contextObservedAt,
        String contextSourceSha256
) {
    private static final String KEY_SEPARATOR = "\u001F";
    private static final Pattern SHA256 = Pattern.compile("^[a-f0-9]{64}$");

    public enum AssetIdentityBasis {
        SOURCE_NAME_ONLY,
        SOURCE_STABLE_ID
    }

    public enum Environment {
        PRODUCTION,
        PRE_PRODUCTION,
        DEVELOPMENT,
        TEST,
        SANDBOX,
        DISASTER_RECOVERY,
        UNKNOWN
    }

    public enum BusinessCriticality {
        MISSION_CRITICAL,
        HIGH,
        MODERATE,
        LOW,
        UNKNOWN
    }

    public AssetContextCsvEvidence {
        if (sourceRowNumber < 2) {
            throw new IllegalArgumentException("sourceRowNumber must be at least 2");
        }
        sourceProfileKey = requireText(sourceProfileKey, "sourceProfileKey");
        Objects.requireNonNull(assetIdentityBasis, "assetIdentityBasis");
        assetObservedName = requireText(assetObservedName, "assetObservedName");
        assetSourceId = assetSourceId == null ? "" : assetSourceId.trim();
        if (assetIdentityBasis == AssetIdentityBasis.SOURCE_NAME_ONLY && !assetSourceId.isEmpty()) {
            throw new IllegalArgumentException(
                    "Asset_Source_ID must be empty when Asset_Identity_Basis is SOURCE_NAME_ONLY");
        }
        if (assetIdentityBasis == AssetIdentityBasis.SOURCE_STABLE_ID && assetSourceId.isEmpty()) {
            throw new IllegalArgumentException(
                    "Asset_Source_ID is required when Asset_Identity_Basis is SOURCE_STABLE_ID");
        }
        Objects.requireNonNull(environment, "environment");
        businessService = requireText(businessService, "businessService");
        businessOwner = requireText(businessOwner, "businessOwner");
        Objects.requireNonNull(businessCriticality, "businessCriticality");
        contextSource = requireText(contextSource, "contextSource");
        Objects.requireNonNull(contextObservedAt, "contextObservedAt");
        contextSourceSha256 = requireText(contextSourceSha256, "contextSourceSha256");
        if (!SHA256.matcher(contextSourceSha256).matches()) {
            throw new IllegalArgumentException("Context_Source_SHA256 must be lowercase SHA-256 hex");
        }
    }

    /** Matches Wazuh NFKC + lowercase identity normalization for either V1 name or V2 stable ID. */
    public String normalizedAssetIdentityKey() {
        String rawIdentity = assetIdentityBasis == AssetIdentityBasis.SOURCE_STABLE_ID
                ? assetSourceId : assetObservedName;
        return normalizeKey(rawIdentity);
    }

    public String normalizedAssetName() {
        return normalizeKey(assetObservedName);
    }

    /** Observation identity used for exact replay/conflict handling. */
    public String observationKey() {
        return String.join(KEY_SEPARATOR,
                sourceProfileKey,
                assetIdentityBasis.name(),
                normalizedAssetIdentityKey(),
                contextSource,
                contextObservedAt.toString());
    }

    /** Immutable content carried by one observation identity. */
    public String normalizedContentKey() {
        return String.join(KEY_SEPARATOR,
                normalizedAssetName(),
                environment.name(),
                businessService,
                businessOwner,
                businessCriticality.name(),
                contextSourceSha256);
    }

    private static String normalizeKey(String value) {
        return Normalizer.normalize(value.trim(), Normalizer.Form.NFKC)
                .toLowerCase(Locale.ROOT);
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }
}
