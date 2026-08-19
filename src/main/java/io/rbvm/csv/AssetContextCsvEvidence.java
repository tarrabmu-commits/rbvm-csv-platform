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
        String assetObservedName,
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
        assetObservedName = requireText(assetObservedName, "assetObservedName");
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

    /** Matches the canonical WAZUH_CSV_V1 name identity normalization. */
    public String normalizedAssetName() {
        return Normalizer.normalize(assetObservedName.trim(), Normalizer.Form.NFKC)
                .toLowerCase(Locale.ROOT);
    }

    /** Observation identity used for exact replay/conflict handling. */
    public String observationKey() {
        return String.join(KEY_SEPARATOR,
                sourceProfileKey,
                normalizedAssetName(),
                contextSource,
                contextObservedAt.toString());
    }

    /** Immutable content carried by one observation identity. */
    public String normalizedContentKey() {
        return String.join(KEY_SEPARATOR,
                environment.name(),
                businessService,
                businessOwner,
                businessCriticality.name(),
                contextSourceSha256);
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }
}
