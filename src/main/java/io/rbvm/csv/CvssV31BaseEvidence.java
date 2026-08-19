package io.rbvm.csv;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * CVE-scoped CVSS v3.1 Base evidence.
 *
 * <p>This type is deliberately independent from threat intelligence and remediation policy. It
 * represents technical severity evidence only: no EPSS, KEV, asset context, priority, SLA, or risk
 * score is derived here.</p>
 */
public record CvssV31BaseEvidence(
        String cveId,
        String version,
        BigDecimal baseScore,
        String vector,
        String source,
        Instant observedAt
) {
    private static final Pattern CVE_PATTERN = Pattern.compile("^CVE-[0-9]{4}-[0-9]{4,}$");
    private static final List<String> BASE_METRIC_ORDER = List.of(
            "AV", "AC", "PR", "UI", "S", "C", "I", "A"
    );
    private static final Map<String, Set<String>> BASE_METRIC_VALUES = Map.of(
            "AV", Set.of("N", "A", "L", "P"),
            "AC", Set.of("L", "H"),
            "PR", Set.of("N", "L", "H"),
            "UI", Set.of("N", "R"),
            "S", Set.of("U", "C"),
            "C", Set.of("H", "L", "N"),
            "I", Set.of("H", "L", "N"),
            "A", Set.of("H", "L", "N")
    );

    public CvssV31BaseEvidence {
        cveId = requireText(cveId, "CVE_ID").toUpperCase(Locale.ROOT);
        if (!CVE_PATTERN.matcher(cveId).matches()) {
            throw new IllegalArgumentException("CVE_ID must match CVE-YYYY-NNNN or longer");
        }

        version = requireText(version, "CVSS_Version");
        if (!version.equals("3.1")) {
            throw new IllegalArgumentException("CVSS_Version must be exactly 3.1");
        }

        Objects.requireNonNull(baseScore, "CVSS_Base_Score");
        if (baseScore.compareTo(BigDecimal.ZERO) < 0
                || baseScore.compareTo(BigDecimal.TEN) > 0) {
            throw new IllegalArgumentException("CVSS_Base_Score must be between 0.0 and 10.0");
        }
        try {
            baseScore = baseScore.setScale(1, RoundingMode.UNNECESSARY);
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException(
                    "CVSS_Base_Score must have at most one decimal place", exception);
        }

        vector = requireText(vector, "CVSS_Vector");
        Map<String, String> metrics = parseBaseMetrics(vector);
        BigDecimal calculatedScore = CvssV31BaseScoreCalculator.calculate(metrics);
        if (baseScore.compareTo(calculatedScore) != 0) {
            throw new IllegalArgumentException(
                    "CVSS_Base_Score must match CVSS_Vector; expected "
                            + calculatedScore.toPlainString()
                            + " but received " + baseScore.toPlainString()
            );
        }

        source = requireText(source, "CVSS_Source");
        validateHttpsSource(source);
        Objects.requireNonNull(observedAt, "CVSS_Observed_At");
    }

    /** Returns the vector in deterministic Base metric order without changing its semantics. */
    public String canonicalVector() {
        Map<String, String> metrics = parseBaseMetrics(vector);
        StringBuilder output = new StringBuilder("CVSS:3.1");
        for (String metric : BASE_METRIC_ORDER) {
            output.append('/').append(metric).append(':').append(metrics.get(metric));
        }
        return output.toString();
    }

    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("cveId", cveId);
        output.put("cvssVersion", version);
        output.put("cvssBaseScore", baseScore.doubleValue());
        output.put("cvssVector", vector);
        output.put("cvssSource", source);
        output.put("cvssObservedAt", observedAt.toString());
        return output;
    }

    static Map<String, String> parseBaseMetrics(String vector) {
        String[] tokens = vector.split("/", -1);
        if (tokens.length == 0 || !tokens[0].equals("CVSS:3.1")) {
            throw new IllegalArgumentException("CVSS_Vector must begin with CVSS:3.1/");
        }

        Map<String, String> metrics = new LinkedHashMap<>();
        for (int index = 1; index < tokens.length; index++) {
            String token = tokens[index];
            String[] pair = token.split(":", -1);
            if (pair.length != 2 || pair[0].isEmpty() || pair[1].isEmpty()) {
                throw new IllegalArgumentException("CVSS_Vector contains an invalid metric token: " + token);
            }
            String metric = pair[0];
            String value = pair[1];
            Set<String> allowed = BASE_METRIC_VALUES.get(metric);
            if (allowed == null) {
                throw new IllegalArgumentException(
                        "CVSS_Vector Base evidence cannot contain non-Base metric: " + metric);
            }
            if (!allowed.contains(value)) {
                throw new IllegalArgumentException(
                        "CVSS_Vector contains invalid value " + value + " for metric " + metric);
            }
            if (metrics.putIfAbsent(metric, value) != null) {
                throw new IllegalArgumentException("CVSS_Vector repeats metric: " + metric);
            }
        }

        if (!metrics.keySet().containsAll(BASE_METRIC_ORDER)
                || metrics.size() != BASE_METRIC_ORDER.size()) {
            List<String> missing = BASE_METRIC_ORDER.stream()
                    .filter(metric -> !metrics.containsKey(metric))
                    .toList();
            throw new IllegalArgumentException(
                    "CVSS_Vector must contain exactly the eight Base metrics; missing: " + missing);
        }
        return Map.copyOf(metrics);
    }

    private static void validateHttpsSource(String source) {
        URI uri;
        try {
            uri = URI.create(source);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("CVSS_Source must be a valid HTTPS URL", exception);
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            throw new IllegalArgumentException("CVSS_Source must be a valid HTTPS URL");
        }
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }
}
