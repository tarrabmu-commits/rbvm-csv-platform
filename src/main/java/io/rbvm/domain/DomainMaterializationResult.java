package io.rbvm.domain;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public record DomainMaterializationResult(
        UUID importId,
        boolean replayed,
        long acceptedObservations,
        long insertedObservations,
        long duplicateObservations,
        long newAssets,
        long newVulnerabilities,
        long newComponents,
        long newExposures,
        long updatedExposures,
        long newCases,
        long updatedCases,
        Instant materializedAt
) {
    public DomainMaterializationResult {
        Objects.requireNonNull(importId, "importId");
        Objects.requireNonNull(materializedAt, "materializedAt");
    }

    public DomainMaterializationResult asReplay() {
        return replayed ? this : new DomainMaterializationResult(
                importId,
                true,
                acceptedObservations,
                insertedObservations,
                duplicateObservations,
                newAssets,
                newVulnerabilities,
                newComponents,
                newExposures,
                updatedExposures,
                newCases,
                updatedCases,
                materializedAt
        );
    }

    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("importId", importId.toString());
        output.put("replayed", replayed);
        output.put("acceptedObservations", acceptedObservations);
        output.put("insertedObservations", insertedObservations);
        output.put("duplicateObservations", duplicateObservations);
        output.put("newAssets", newAssets);
        output.put("newVulnerabilities", newVulnerabilities);
        output.put("newComponents", newComponents);
        output.put("newExposures", newExposures);
        output.put("updatedExposures", updatedExposures);
        output.put("newCases", newCases);
        output.put("updatedCases", updatedCases);
        output.put("materializedAt", materializedAt.toString());
        return output;
    }
}
