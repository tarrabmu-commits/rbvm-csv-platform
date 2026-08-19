package io.rbvm.csv;

import java.text.Normalizer;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * One source- and time-bounded network reachability observation to a canonical asset endpoint.
 *
 * <p>This is technical connectivity evidence only. It does not encode exploitability, asset
 * criticality, organizational risk, priority, or treatment policy.</p>
 */
public record NetworkReachabilityCsvEvidence(
        long sourceRowNumber,
        String sourceProfileKey,
        AssetIdentityBasis assetIdentityBasis,
        String assetObservedName,
        String assetSourceId,
        OriginScope originScope,
        String originLabel,
        TransportProtocol transportProtocol,
        Integer targetPort,
        String targetService,
        ReachabilityStatus reachabilityStatus,
        ReachabilityMethod reachabilityMethod,
        String evidenceSource,
        Instant evidenceObservedAt,
        String evidenceSourceSha256
) {
    private static final String KEY_SEPARATOR = "\u001F";
    private static final Pattern SHA256 = Pattern.compile("^[a-f0-9]{64}$");

    public enum AssetIdentityBasis {
        SOURCE_NAME_ONLY,
        SOURCE_STABLE_ID
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

    public enum ReachabilityStatus {
        REACHABLE,
        NOT_REACHABLE,
        UNKNOWN
    }

    public enum ReachabilityMethod {
        ACTIVE_PROBE,
        CONTROL_PLANE,
        FIREWALL_POLICY,
        CLOUD_CONFIGURATION,
        PASSIVE_OBSERVATION,
        OTHER,
        UNKNOWN
    }

    public NetworkReachabilityCsvEvidence {
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
        Objects.requireNonNull(originScope, "originScope");
        originLabel = requireText(originLabel, "originLabel");
        Objects.requireNonNull(transportProtocol, "transportProtocol");
        if (targetPort != null && (targetPort < 1 || targetPort > 65_535)) {
            throw new IllegalArgumentException("Target_Port must be between 1 and 65535 when present");
        }
        if ((transportProtocol == TransportProtocol.TCP
                || transportProtocol == TransportProtocol.UDP) && targetPort == null) {
            throw new IllegalArgumentException("Target_Port is required for TCP or UDP evidence");
        }
        if (transportProtocol == TransportProtocol.ICMP && targetPort != null) {
            throw new IllegalArgumentException("Target_Port must be empty for ICMP evidence");
        }
        targetService = requireText(targetService, "targetService");
        Objects.requireNonNull(reachabilityStatus, "reachabilityStatus");
        Objects.requireNonNull(reachabilityMethod, "reachabilityMethod");
        evidenceSource = requireText(evidenceSource, "evidenceSource");
        Objects.requireNonNull(evidenceObservedAt, "evidenceObservedAt");
        evidenceSourceSha256 = requireText(evidenceSourceSha256, "evidenceSourceSha256");
        if (!SHA256.matcher(evidenceSourceSha256).matches()) {
            throw new IllegalArgumentException("Evidence_Source_SHA256 must be lowercase SHA-256 hex");
        }
    }

    /** Matches Wazuh NFKC + trim + lowercase identity normalization for V1/V2 assets. */
    public String normalizedAssetIdentityKey() {
        String rawIdentity = assetIdentityBasis == AssetIdentityBasis.SOURCE_STABLE_ID
                ? assetSourceId : assetObservedName;
        return normalizeKey(rawIdentity);
    }

    public String normalizedAssetName() {
        return normalizeKey(assetObservedName);
    }

    /**
     * One scoped path/endpoint observation identity. The result does not imply global isolation or
     * global exposure outside this origin, endpoint, source, and observation time.
     */
    public String observationKey() {
        return String.join(KEY_SEPARATOR,
                sourceProfileKey,
                assetIdentityBasis.name(),
                normalizedAssetIdentityKey(),
                originScope.name(),
                normalizeKey(originLabel),
                transportProtocol.name(),
                targetPort == null ? "" : targetPort.toString(),
                evidenceSource,
                evidenceObservedAt.toString());
    }

    public String normalizedContentKey() {
        return String.join(KEY_SEPARATOR,
                normalizedAssetName(),
                targetService,
                reachabilityStatus.name(),
                reachabilityMethod.name(),
                evidenceSourceSha256);
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
