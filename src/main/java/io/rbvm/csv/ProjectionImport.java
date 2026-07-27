package io.rbvm.csv;

import io.rbvm.domain.DomainMaterializationResult;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record ProjectionImport(
        UUID importId,
        Path rawEvidence,
        String sourceProfileId,
        AnalysisReport analysis,
        DomainMaterializationResult localMaterialization,
        Instant createdAt
) {
    public ProjectionImport {
        Objects.requireNonNull(importId, "importId");
        Objects.requireNonNull(rawEvidence, "rawEvidence");
        Objects.requireNonNull(sourceProfileId, "sourceProfileId");
        Objects.requireNonNull(analysis, "analysis");
        Objects.requireNonNull(localMaterialization, "localMaterialization");
        Objects.requireNonNull(createdAt, "createdAt");
    }
}
