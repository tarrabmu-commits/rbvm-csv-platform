package io.rbvm.csv;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Explicit statement of what a supported Wazuh CSV contract can prove.
 *
 * <p>This is deliberately capability-based rather than confidence-scored. Missing source
 * evidence must remain missing; the platform must not invent stable asset identity, package
 * coordinates, or remediation lifecycle facts that were not supplied by the source.</p>
 */
public record WazuhEvidenceCapabilities(
        boolean stableAssetId,
        boolean packageVersion,
        boolean packageArchitecture,
        boolean explicitFindingLifecycle
) {
    public static WazuhEvidenceCapabilities forContract(String contractId) {
        String supported = CsvContractV2.requireSupported(contractId);
        if (CsvContractV2.ID.equals(supported)) {
            return new WazuhEvidenceCapabilities(true, true, true, true);
        }
        return new WazuhEvidenceCapabilities(false, false, false, false);
    }

    public boolean rbvmFindingIdentityReady() {
        return stableAssetId && packageVersion && packageArchitecture;
    }

    public boolean rbvmLifecycleReady() {
        return explicitFindingLifecycle;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("stableAssetId", stableAssetId);
        output.put("packageVersion", packageVersion);
        output.put("packageArchitecture", packageArchitecture);
        output.put("explicitFindingLifecycle", explicitFindingLifecycle);
        output.put("rbvmFindingIdentityReady", rbvmFindingIdentityReady());
        output.put("rbvmLifecycleReady", rbvmLifecycleReady());
        return output;
    }
}
