package io.rbvm.postgres;

import java.io.IOException;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Exact CSV-first priority -> canonical Finding materialization boundary. */
public interface CanonicalMvpPriorityStore {
    String METHOD_ID = "RBVM_MVP_PRIORITY_POLICY_V1";
    String METHOD_SHA256 = "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388";

    MaterializationResult materialize(
            UUID importId,
            UUID csvRunId,
            UUID analysisId,
            String sourceCsvSha256,
            String priorityCsvSha256,
            List<PriorityRow> rows,
            Instant materializedAt
    ) throws IOException;

    default Optional<PriorityView> latestForFinding(String findingId) throws IOException {
        return Optional.empty();
    }

    record PriorityRow(
            long sourceRowNumber,
            String status,
            Integer front,
            Long dominatedBy,
            Long dominates,
            String blockers,
            String explanation,
            String methodSha256,
            Boolean kevListed,
            String internetFacing,
            String assetCriticality,
            BigDecimal epssProbability,
            BigDecimal contextualCvssV4
    ) {
    }

    record MaterializationResult(
            int canonicalFindings,
            int insertedResults,
            int replayedResults,
            int mappedSourceRows,
            String sourceCsvSha256,
            String priorityCsvSha256
    ) {
    }

    record PriorityView(
            String findingId,
            UUID importId,
            UUID csvRunId,
            UUID analysisId,
            String status,
            Integer front,
            Long dominatedBy,
            Long dominates,
            String blockers,
            String explanation,
            Boolean kevListed,
            String internetFacing,
            String assetCriticality,
            BigDecimal epssProbability,
            BigDecimal contextualCvssV4,
            List<Long> sourceRowNumbers,
            String sourceCsvSha256,
            String priorityCsvSha256,
            String resultSha256,
            Instant materializedAt
    ) {
    }

    final class ConflictException extends IOException {
        public ConflictException(String message) {
            super(message);
        }
    }

    final class NotFoundException extends IOException {
        public NotFoundException(String message) {
            super(message);
        }
    }
}
