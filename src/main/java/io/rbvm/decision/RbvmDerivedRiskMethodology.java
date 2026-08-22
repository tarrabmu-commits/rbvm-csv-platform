package io.rbvm.decision;

import java.math.BigDecimal;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Pure deterministic contract for risk methodologies derived from a published external model.
 *
 * <p>A derived methodology must expose the provider/source identity and a SHA-bound RBVM mapping.
 * The external source equation and the RBVM input mapping are deliberately distinct concepts: a
 * result must never be represented as an official vendor score when RBVM supplies its own mapping
 * from Decision Input evidence into the source model's variables.</p>
 */
public interface RbvmDerivedRiskMethodology {
    enum Classification {
        STANDARD_DERIVED
    }

    enum ResultState {
        COMPUTED,
        NOT_APPLICABLE,
        NON_COMPUTABLE
    }

    record Definition(
            String methodologyId,
            int version,
            Classification classification,
            String provider,
            String sourceModel,
            String sourceEquation,
            String sourceUrl,
            String methodologySha256,
            String outputName
    ) {
        public Definition {
            methodologyId = requireText(methodologyId, "methodologyId");
            if (version < 1) {
                throw new IllegalArgumentException("version must be positive");
            }
            classification = Objects.requireNonNull(classification, "classification");
            provider = requireText(provider, "provider");
            sourceModel = requireText(sourceModel, "sourceModel");
            sourceEquation = requireText(sourceEquation, "sourceEquation");
            sourceUrl = requireText(sourceUrl, "sourceUrl");
            if (!sourceUrl.startsWith("https://")) {
                throw new IllegalArgumentException("sourceUrl must use HTTPS");
            }
            methodologySha256 = requireSha(methodologySha256, "methodologySha256");
            outputName = requireText(outputName, "outputName");
        }
    }

    /** One visible intermediate value used to reproduce the methodology result. */
    record Measure(
            String measureId,
            String role,
            BigDecimal value,
            String scale
    ) {
        public Measure {
            measureId = requireText(measureId, "measureId");
            role = requireText(role, "role");
            value = Objects.requireNonNull(value, "value");
            scale = requireText(scale, "scale");
        }
    }

    /**
     * Ephemeral result for one exact Decision Input V3 snapshot.
     *
     * <p>{@code rating} is the source-model/derived methodology rating when that methodology defines
     * one. It is never remediation Priority, Treatment, or SLA.</p>
     */
    record Evaluation(
            ResultState state,
            String reasonCode,
            Definition definition,
            String inputContractId,
            String inputSnapshotSha256,
            UUID findingId,
            BigDecimal numericScore,
            String numericScale,
            String rating,
            List<Measure> measures
    ) {
        public Evaluation {
            state = Objects.requireNonNull(state, "state");
            definition = Objects.requireNonNull(definition, "definition");
            inputContractId = requireText(inputContractId, "inputContractId");
            inputSnapshotSha256 = requireSha(inputSnapshotSha256, "inputSnapshotSha256");
            findingId = Objects.requireNonNull(findingId, "findingId");
            measures = List.copyOf(Objects.requireNonNull(measures, "measures"));

            if (state == ResultState.COMPUTED) {
                if (reasonCode != null) {
                    throw new IllegalArgumentException("COMPUTED result must not carry reasonCode");
                }
                numericScore = Objects.requireNonNull(numericScore, "numericScore");
                numericScale = requireText(numericScale, "numericScale");
                if (rating != null) {
                    rating = requireText(rating, "rating");
                }
                if (measures.isEmpty()) {
                    throw new IllegalArgumentException("COMPUTED result must expose measures");
                }
            } else {
                reasonCode = requireText(reasonCode, "reasonCode");
                if (numericScore != null || numericScale != null || rating != null) {
                    throw new IllegalArgumentException(
                            "Terminal result must not carry numeric score, scale, or rating");
                }
                if (!measures.isEmpty()) {
                    throw new IllegalArgumentException(
                            "Terminal result must not carry partial numeric measures");
                }
            }
        }
    }

    Definition definition();

    Evaluation evaluate(RbvmResolvedDecisionInput input);

    private static String requireText(String value, String field) {
        if (value == null || value.trim().isEmpty() || value.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " must be non-empty text");
        }
        return value.trim();
    }

    private static String requireSha(String value, String field) {
        String normalized = requireText(value, field);
        if (!normalized.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
        return normalized;
    }
}
