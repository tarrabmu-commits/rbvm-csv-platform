package io.rbvm.csv;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * CVE-scoped FIRST EPSS exploitation-probability evidence.
 *
 * <p>This type preserves source probability evidence only. It deliberately does not derive
 * organizational risk, priority, SLA, CVSS/KEV combinations, asset context, or business impact.</p>
 */
public record EpssEvidence(
        String cveId,
        BigDecimal probability,
        BigDecimal percentile,
        String modelVersion,
        LocalDate scoreDate,
        String source,
        Instant observedAt,
        String sourceSha256
) {
    public static final String FIRST_EPSS_SOURCE =
            "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

    private static final Pattern CVE_PATTERN = Pattern.compile("^CVE-[0-9]{4}-[0-9]{4,}$");
    private static final Pattern MODEL_VERSION_PATTERN =
            Pattern.compile("^v?[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}$");
    private static final Pattern SHA256_PATTERN = Pattern.compile("^[a-f0-9]{64}$");

    public EpssEvidence {
        cveId = requireText(cveId, "CVE_ID").toUpperCase(Locale.ROOT);
        if (!CVE_PATTERN.matcher(cveId).matches()) {
            throw new IllegalArgumentException("CVE_ID must match CVE-YYYY-NNNN or longer");
        }

        probability = canonicalProbability(probability, "EPSS_Probability");
        percentile = canonicalProbability(percentile, "EPSS_Percentile");

        modelVersion = requireText(modelVersion, "EPSS_Model_Version");
        if (!MODEL_VERSION_PATTERN.matcher(modelVersion).matches()) {
            throw new IllegalArgumentException(
                    "EPSS_Model_Version must match the FIRST model-version date format");
        }

        Objects.requireNonNull(scoreDate, "EPSS_Score_Date");
        source = requireText(source, "EPSS_Source");
        if (!source.equals(FIRST_EPSS_SOURCE)) {
            throw new IllegalArgumentException(
                    "EPSS_Source must be the pinned official FIRST daily bulk feed");
        }
        Objects.requireNonNull(observedAt, "EPSS_Observed_At");

        sourceSha256 = requireText(sourceSha256, "EPSS_Source_SHA256").toLowerCase(Locale.ROOT);
        if (!SHA256_PATTERN.matcher(sourceSha256).matches()) {
            throw new IllegalArgumentException(
                    "EPSS_Source_SHA256 must be 64 hexadecimal characters");
        }
    }

    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("cveId", cveId);
        output.put("epssProbability", probability.doubleValue());
        output.put("epssPercentile", percentile.doubleValue());
        output.put("epssModelVersion", modelVersion);
        output.put("epssScoreDate", scoreDate.toString());
        output.put("epssSource", source);
        output.put("epssObservedAt", observedAt.toString());
        output.put("epssSourceSha256", sourceSha256);
        return Map.copyOf(output);
    }

    private static BigDecimal canonicalProbability(BigDecimal value, String field) {
        Objects.requireNonNull(value, field);
        if (value.compareTo(BigDecimal.ZERO) < 0 || value.compareTo(BigDecimal.ONE) > 0) {
            throw new IllegalArgumentException(field + " must be between 0 and 1");
        }
        return value.stripTrailingZeros();
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }
}
