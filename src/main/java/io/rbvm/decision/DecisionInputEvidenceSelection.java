package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.NativeEvidenceKind;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.FreshnessMode;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.SourceSelectionMode;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Pure selection semantics for constructing one Decision Input Snapshot dimension from native
 * evidence candidates. This class does not query persistence and does not calculate a decision.
 */
public final class DecisionInputEvidenceSelection {
    private DecisionInputEvidenceSelection() {
    }

    /**
     * Selects latest admissible evidence independently per semantic source and native evidence kind
     * within each sub-grain. The methodology allowlist still filters semantic source only; native
     * kind prevents two independent native stores from being silently coalesced.
     */
    public static Selection select(
            EvidenceSelectionPolicy policy,
            Instant evaluatedAt,
            List<Candidate> candidates
    ) {
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        Objects.requireNonNull(candidates, "candidates");

        Map<String, Map<SourceIdentity, List<Candidate>>> bySubgrainAndSource = new HashMap<>();
        for (Candidate candidate : candidates) {
            Objects.requireNonNull(candidate, "candidates must not contain null");
            if (candidate.dimension() != policy.dimension()) {
                throw new IllegalArgumentException(
                        "Candidate dimension must match the evidence-selection policy dimension");
            }
            if (candidate.observedAt().isAfter(evaluatedAt)) {
                continue;
            }
            if (!sourceAllowed(policy, candidate.evidenceSource())) {
                continue;
            }
            SourceIdentity sourceIdentity = new SourceIdentity(
                    candidate.evidenceSource(),
                    candidate.nativeEvidenceKind()
            );
            bySubgrainAndSource
                    .computeIfAbsent(candidate.subgrainKey(), ignored -> new HashMap<>())
                    .computeIfAbsent(sourceIdentity, ignored -> new ArrayList<>())
                    .add(candidate);
        }

        List<SelectedCandidate> selected = new ArrayList<>();
        boolean ambiguous = false;
        boolean stale = false;

        List<String> subgrainKeys = new ArrayList<>(bySubgrainAndSource.keySet());
        subgrainKeys.sort(String::compareTo);
        for (String subgrainKey : subgrainKeys) {
            Map<SourceIdentity, List<Candidate>> bySource =
                    bySubgrainAndSource.get(subgrainKey);
            List<SelectedCandidate> subgrainSelected = new ArrayList<>();

            List<SourceIdentity> sources = new ArrayList<>(bySource.keySet());
            sources.sort(Comparator
                    .comparing(SourceIdentity::source)
                    .thenComparing(item -> item.nativeEvidenceKind().name()));
            for (SourceIdentity source : sources) {
                List<Candidate> sourceCandidates = bySource.get(source);
                Instant latest = sourceCandidates.stream()
                        .map(Candidate::observedAt)
                        .max(Instant::compareTo)
                        .orElseThrow();
                sourceCandidates.stream()
                        .filter(candidate -> candidate.observedAt().equals(latest))
                        .sorted(Comparator
                                .comparing((Candidate candidate) ->
                                        candidate.nativeEvidenceKind().name())
                                .thenComparing(Candidate::evidenceId))
                        .map(candidate -> new SelectedCandidate(
                                candidate,
                                isStale(policy, evaluatedAt, candidate.observedAt())
                        ))
                        .forEach(subgrainSelected::add);
            }

            if (subgrainSelected.size() > 1) {
                ambiguous = true;
            }
            if (subgrainSelected.stream().anyMatch(SelectedCandidate::stale)) {
                stale = true;
            }
            selected.addAll(subgrainSelected);
        }

        selected.sort(Comparator
                .comparing((SelectedCandidate item) -> item.candidate().subgrainKey())
                .thenComparing(item -> item.candidate().evidenceSource())
                .thenComparing(item -> item.candidate().nativeEvidenceKind().name())
                .thenComparing(item -> item.candidate().observedAt())
                .thenComparing(item -> item.candidate().evidenceId()));

        DimensionState state;
        if (selected.isEmpty()) {
            state = DimensionState.MISSING;
        } else if (ambiguous) {
            state = DimensionState.AMBIGUOUS;
        } else if (stale) {
            state = DimensionState.STALE;
        } else {
            state = DimensionState.PRESENT;
        }

        List<EvidenceReference> references = selected.stream()
                .map(SelectedCandidate::candidate)
                .map(Candidate::toEvidenceReference)
                .toList();
        Map<String, Integer> subgrainReferenceCounts = new LinkedHashMap<>();
        for (SelectedCandidate item : selected) {
            subgrainReferenceCounts.merge(item.candidate().subgrainKey(), 1, Integer::sum);
        }
        return new Selection(
                policy.dimension(),
                state,
                references,
                subgrainReferenceCounts,
                ambiguous,
                stale
        );
    }

    private static boolean sourceAllowed(EvidenceSelectionPolicy policy, String source) {
        if (policy.sourceSelectionMode() == SourceSelectionMode.ALL_SOURCES) {
            return true;
        }
        return policy.sourceAllowlist().contains(source);
    }

    private static boolean isStale(
            EvidenceSelectionPolicy policy,
            Instant evaluatedAt,
            Instant observedAt
    ) {
        if (policy.freshnessMode() == FreshnessMode.NO_AGE_LIMIT) {
            return false;
        }
        long maximumAgeSeconds = Objects.requireNonNull(policy.maximumAgeSeconds());
        Duration age = Duration.between(observedAt, evaluatedAt);
        return age.compareTo(Duration.ofSeconds(maximumAgeSeconds)) > 0;
    }

    /** Native-evidence metadata required before an evidence row can enter snapshot selection. */
    public record Candidate(
            EvidenceDimension dimension,
            String subgrainKey,
            NativeEvidenceKind nativeEvidenceKind,
            UUID evidenceId,
            String evidenceSha256,
            String evidenceSource,
            Instant observedAt,
            BindingReference bindingReference
    ) {
        /** Historical constructor for dimensions that have one native evidence store. */
        public Candidate(
                EvidenceDimension dimension,
                String subgrainKey,
                UUID evidenceId,
                String evidenceSha256,
                String evidenceSource,
                Instant observedAt
        ) {
            this(
                    dimension,
                    subgrainKey,
                    NativeEvidenceKind.defaultFor(dimension),
                    evidenceId,
                    evidenceSha256,
                    evidenceSource,
                    observedAt,
                    null
            );
        }

        public Candidate {
            dimension = Objects.requireNonNull(dimension, "dimension");
            subgrainKey = requireText(subgrainKey, "subgrainKey", 1024);
            nativeEvidenceKind = Objects.requireNonNull(
                    nativeEvidenceKind,
                    "nativeEvidenceKind"
            );
            if (!nativeEvidenceKind.supports(dimension)) {
                throw new IllegalArgumentException(
                        "nativeEvidenceKind is incompatible with candidate dimension");
            }
            evidenceId = Objects.requireNonNull(evidenceId, "evidenceId");
            if (evidenceSha256 == null || !evidenceSha256.matches("[a-f0-9]{64}")) {
                throw new IllegalArgumentException("evidenceSha256 must be lowercase SHA-256");
            }
            evidenceSource = requireText(evidenceSource, "evidenceSource", 256);
            observedAt = Objects.requireNonNull(observedAt, "observedAt");
            if (nativeEvidenceKind == NativeEvidenceKind.MANAGED_ASSET_REVISION) {
                Objects.requireNonNull(
                        bindingReference,
                        "managed asset revision candidate requires bindingReference"
                );
            } else if (bindingReference != null) {
                throw new IllegalArgumentException(
                        "bindingReference is only supported for managed asset revision candidates");
            }
        }

        private EvidenceReference toEvidenceReference() {
            return new EvidenceReference(
                    dimension,
                    nativeEvidenceKind,
                    evidenceId,
                    evidenceSha256,
                    evidenceSource,
                    observedAt,
                    bindingReference
            );
        }
    }

    public record Selection(
            EvidenceDimension dimension,
            DimensionState state,
            List<EvidenceReference> evidenceReferences,
            Map<String, Integer> subgrainReferenceCounts,
            boolean hasAmbiguousSubgrain,
            boolean hasStaleReference
    ) {
        public Selection {
            dimension = Objects.requireNonNull(dimension, "dimension");
            state = Objects.requireNonNull(state, "state");
            evidenceReferences = List.copyOf(evidenceReferences);
            subgrainReferenceCounts = Map.copyOf(subgrainReferenceCounts);
            if (state == DimensionState.MISSING && !evidenceReferences.isEmpty()) {
                throw new IllegalArgumentException("MISSING selection must not contain references");
            }
            if (state != DimensionState.MISSING && evidenceReferences.isEmpty()) {
                throw new IllegalArgumentException("Non-missing selection requires references");
            }
            if (hasAmbiguousSubgrain != (state == DimensionState.AMBIGUOUS)) {
                throw new IllegalArgumentException(
                        "AMBIGUOUS state must exactly match an ambiguous selected sub-grain");
            }
        }
    }

    private record SelectedCandidate(Candidate candidate, boolean stale) {
    }

    private record SourceIdentity(String source, NativeEvidenceKind nativeEvidenceKind) {
        private SourceIdentity {
            Objects.requireNonNull(source, "source");
            Objects.requireNonNull(nativeEvidenceKind, "nativeEvidenceKind");
        }
    }

    private static String requireText(String value, String field, int maximumLength) {
        if (value == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
        String normalized = value.trim();
        if (normalized.isEmpty() || normalized.length() > maximumLength
                || normalized.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return normalized;
    }
}
