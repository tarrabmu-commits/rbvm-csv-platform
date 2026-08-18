package io.rbvm.csv;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Stable grouping identity for one logical vulnerability finding across repeated source observations.
 *
 * <p>The identity is intentionally limited to facts that the selected Wazuh source contract can
 * actually prove. V1 therefore remains name-scoped and product-scoped, while V2 can use stable
 * Agent_ID plus package version and architecture. This type is not a risk score and does not infer
 * applicability, exploitability, or remediation.</p>
 */
public record CanonicalFindingIdentity(
        String sourceProfileId,
        String assetIdentityKey,
        String cveId,
        String componentIdentityKey,
        Strength strength
) {
    private static final String KEY_SEPARATOR = "\u001F";

    public enum Strength {
        SOURCE_LIMITED,
        SOURCE_STABLE
    }

    public CanonicalFindingIdentity {
        sourceProfileId = requireText(sourceProfileId, "sourceProfileId");
        assetIdentityKey = requireText(assetIdentityKey, "assetIdentityKey");
        cveId = requireText(cveId, "cveId");
        componentIdentityKey = requireText(componentIdentityKey, "componentIdentityKey");
        Objects.requireNonNull(strength, "strength");
    }

    public static CanonicalFindingIdentity from(WazuhObservation observation) {
        Objects.requireNonNull(observation, "observation");
        WazuhEvidenceCapabilities capabilities = observation.evidenceCapabilities();
        return new CanonicalFindingIdentity(
                observation.sourceProfileId(),
                observation.agentIdentityKey(),
                observation.cveId(),
                observation.affectedProductIdentityKey(),
                capabilities.rbvmFindingIdentityReady() ? Strength.SOURCE_STABLE : Strength.SOURCE_LIMITED
        );
    }

    /**
     * Deterministic natural key used only for grouping observations into one logical finding.
     */
    public String naturalKey() {
        return String.join(KEY_SEPARATOR,
                sourceProfileId,
                assetIdentityKey,
                cveId,
                componentIdentityKey);
    }

    public boolean isSourceStable() {
        return strength == Strength.SOURCE_STABLE;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("sourceProfileId", sourceProfileId);
        output.put("assetIdentityKey", assetIdentityKey);
        output.put("cveId", cveId);
        output.put("componentIdentityKey", componentIdentityKey);
        output.put("strength", strength.name());
        output.put("sourceStable", isSourceStable());
        output.put("naturalKey", naturalKey());
        return output;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }
}
