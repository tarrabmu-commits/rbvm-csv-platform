package io.rbvm.csv;

import java.text.Normalizer;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * One source-reported qualitative business/mission impact observation for an asset-service pair.
 *
 * <p>The platform preserves this as evidence. The qualitative level is not a numeric weight,
 * monetary-loss model, risk score, priority, or SLA.</p>
 */
public record BusinessImpactCsvEvidence(
        long sourceRowNumber,
        String sourceProfileKey,
        AssetIdentityBasis assetIdentityBasis,
        String assetObservedName,
        String assetSourceId,
        String businessService,
        ImpactDimension impactDimension,
        ImpactLevel impactLevel,
        ImpactMethod impactMethod,
        String impactStatement,
        String impactSource,
        Instant impactObservedAt,
        String impactSourceSha256
) {
    private static final String KEY_SEPARATOR = "\u001F";
    private static final Pattern SHA256 = Pattern.compile("^[a-f0-9]{64}$");

    public enum AssetIdentityBasis {
        SOURCE_NAME_ONLY,
        SOURCE_STABLE_ID
    }

    public enum ImpactDimension {
        AVAILABILITY,
        INTEGRITY,
        CONFIDENTIALITY,
        SAFETY,
        FINANCIAL,
        REGULATORY,
        OPERATIONAL,
        REPUTATIONAL,
        MISSION,
        OTHER,
        UNKNOWN
    }

    public enum ImpactLevel {
        SEVERE,
        HIGH,
        MODERATE,
        LOW,
        NEGLIGIBLE,
        UNKNOWN
    }

    public enum ImpactMethod {
        BUSINESS_IMPACT_ANALYSIS,
        SERVICE_OWNER_ATTESTATION,
        POLICY_CLASSIFICATION,
        INCIDENT_ANALYSIS,
        OTHER,
        UNKNOWN
    }

    public BusinessImpactCsvEvidence {
        if (sourceRowNumber < 2) {
            throw new IllegalArgumentException("sourceRowNumber must be at least 2");
        }
        sourceProfileKey = requireText(sourceProfileKey, "sourceProfileKey", 128);
        Objects.requireNonNull(assetIdentityBasis, "assetIdentityBasis");
        assetObservedName = requireText(assetObservedName, "assetObservedName", 160);
        assetSourceId = assetSourceId == null ? "" : assetSourceId.trim();
        if (assetSourceId.length() > 160) {
            throw new IllegalArgumentException("Asset_Source_ID exceeds 160 characters");
        }
        if (assetIdentityBasis == AssetIdentityBasis.SOURCE_NAME_ONLY && !assetSourceId.isEmpty()) {
            throw new IllegalArgumentException(
                    "Asset_Source_ID must be empty when Asset_Identity_Basis is SOURCE_NAME_ONLY");
        }
        if (assetIdentityBasis == AssetIdentityBasis.SOURCE_STABLE_ID && assetSourceId.isEmpty()) {
            throw new IllegalArgumentException(
                    "Asset_Source_ID is required when Asset_Identity_Basis is SOURCE_STABLE_ID");
        }
        businessService = requireText(businessService, "businessService", 256);
        Objects.requireNonNull(impactDimension, "impactDimension");
        Objects.requireNonNull(impactLevel, "impactLevel");
        Objects.requireNonNull(impactMethod, "impactMethod");
        impactStatement = requireText(impactStatement, "impactStatement", 2_048);
        impactSource = requireText(impactSource, "impactSource", 256);
        Objects.requireNonNull(impactObservedAt, "impactObservedAt");
        impactSourceSha256 = requireText(impactSourceSha256, "impactSourceSha256", 64);
        if (!SHA256.matcher(impactSourceSha256).matches()) {
            throw new IllegalArgumentException("Impact_Source_SHA256 must be lowercase SHA-256 hex");
        }
    }

    /** Matches Wazuh NFKC + trim + lowercase identity normalization for V1/V2 assets. */
    public String normalizedAssetIdentityKey() {
        String raw = assetIdentityBasis == AssetIdentityBasis.SOURCE_STABLE_ID
                ? assetSourceId : assetObservedName;
        return normalizeKey(raw);
    }

    public String normalizedAssetName() {
        return normalizeKey(assetObservedName);
    }

    public String normalizedBusinessService() {
        return normalizeKey(businessService);
    }

    /** One source/time/dimension observation identity; different sources remain independent. */
    public String observationKey() {
        return String.join(KEY_SEPARATOR,
                sourceProfileKey,
                assetIdentityBasis.name(),
                normalizedAssetIdentityKey(),
                normalizedBusinessService(),
                impactDimension.name(),
                impactSource,
                impactObservedAt.toString());
    }

    public String normalizedContentKey() {
        return String.join(KEY_SEPARATOR,
                normalizedAssetName(),
                impactLevel.name(),
                impactMethod.name(),
                normalizeStatement(impactStatement),
                impactSourceSha256);
    }

    private static String normalizeStatement(String value) {
        return Normalizer.normalize(value.trim(), Normalizer.Form.NFKC);
    }

    private static String normalizeKey(String value) {
        return Normalizer.normalize(value.trim(), Normalizer.Form.NFKC)
                .toLowerCase(Locale.ROOT);
    }

    private static String requireText(String value, String field, int maximumLength) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        String trimmed = value.trim();
        if (trimmed.length() > maximumLength || trimmed.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " is invalid or too long");
        }
        return trimmed;
    }
}
