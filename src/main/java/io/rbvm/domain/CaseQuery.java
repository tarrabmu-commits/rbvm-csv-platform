package io.rbvm.domain;

import io.rbvm.csv.CsvSeverity;

import java.util.Set;

public record CaseQuery(
        int limit,
        String cursor,
        Set<CsvSeverity> severities,
        Set<CaseStatus> statuses,
        String cveContains,
        String assetContains,
        Set<VulnerabilityPriorityTier> priorityTiers,
        Boolean knownExploited
) {
    public CaseQuery(int limit, String cursor, Set<CsvSeverity> severities,
                     Set<CaseStatus> statuses, String cveContains, String assetContains) {
        this(limit, cursor, severities, statuses, cveContains, assetContains, Set.of(), null);
    }

    public CaseQuery {
        if (limit < 0 || limit > 100) {
            throw new IllegalArgumentException("limit must be between 0 and 100");
        }
        cursor = normalize(cursor);
        severities = severities == null ? Set.of() : Set.copyOf(severities);
        statuses = statuses == null ? Set.of() : Set.copyOf(statuses);
        cveContains = normalize(cveContains);
        assetContains = normalize(assetContains);
        priorityTiers = priorityTiers == null ? Set.of() : Set.copyOf(priorityTiers);
    }

    public static CaseQuery firstPage(int limit) {
        return new CaseQuery(limit, null, Set.of(), Set.of(), null, null, Set.of(), null);
    }

    private static String normalize(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
