package io.rbvm.domain;

import java.util.LinkedHashMap;
import java.util.Map;

public record CatalogSnapshot(
        long materializedImports,
        long observations,
        long importObservationLinks,
        long assets,
        long vulnerabilities,
        long components,
        long exposures,
        long cases,
        long openCases,
        long autoClosedCases,
        long exposuresWithSeverityChanges,
        long exposuresWithTimestampConflicts,
        Map<String, Long> currentCaseSeverityDistribution,
        Map<String, Long> caseStatusDistribution
) {
    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("materializedImports", materializedImports);
        output.put("observations", observations);
        output.put("importObservationLinks", importObservationLinks);
        output.put("assets", assets);
        output.put("vulnerabilities", vulnerabilities);
        output.put("components", components);
        output.put("exposures", exposures);
        output.put("cases", cases);
        output.put("openCases", openCases);
        output.put("autoClosedCases", autoClosedCases);
        output.put("exposuresWithSeverityChanges", exposuresWithSeverityChanges);
        output.put("exposuresWithTimestampConflicts", exposuresWithTimestampConflicts);
        output.put("currentCaseSeverityDistribution", currentCaseSeverityDistribution);
        output.put("caseStatusDistribution", caseStatusDistribution);
        output.put("closurePolicy", "POSITIVE_ONLY_NO_AUTO_CLOSE");
        return output;
    }
}
