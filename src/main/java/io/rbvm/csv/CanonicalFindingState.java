package io.rbvm.csv;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Evidence-derived state for one canonical vulnerability finding.
 *
 * <p>This state aggregates repeated immutable Wazuh observations without inventing facts that the
 * source contract cannot prove. In particular, V1 is observation-only and cannot prove remediation;
 * V2 may carry explicit ACTIVE/RESOLVED lifecycle evidence.</p>
 */
public final class CanonicalFindingState {
    public enum SourceState {
        OBSERVED_ONLY,
        ACTIVE,
        RESOLVED
    }

    private final CanonicalFindingIdentity identity;
    private final Instant firstObservedAt;
    private final Instant lastObservedAt;
    private final Instant stateEvidenceAt;
    private final SourceState sourceState;
    private final boolean explicitLifecycle;
    private final Set<String> observationFingerprints;

    private CanonicalFindingState(
            CanonicalFindingIdentity identity,
            Instant firstObservedAt,
            Instant lastObservedAt,
            Instant stateEvidenceAt,
            SourceState sourceState,
            boolean explicitLifecycle,
            Set<String> observationFingerprints
    ) {
        this.identity = Objects.requireNonNull(identity, "identity");
        this.firstObservedAt = Objects.requireNonNull(firstObservedAt, "firstObservedAt");
        this.lastObservedAt = Objects.requireNonNull(lastObservedAt, "lastObservedAt");
        this.stateEvidenceAt = Objects.requireNonNull(stateEvidenceAt, "stateEvidenceAt");
        this.sourceState = Objects.requireNonNull(sourceState, "sourceState");
        this.explicitLifecycle = explicitLifecycle;
        if (lastObservedAt.isBefore(firstObservedAt)) {
            throw new IllegalArgumentException("lastObservedAt must not be before firstObservedAt");
        }
        if (!explicitLifecycle && sourceState != SourceState.OBSERVED_ONLY) {
            throw new IllegalArgumentException(
                    "Observation-only source evidence cannot assert ACTIVE or RESOLVED state");
        }
        if (explicitLifecycle && sourceState == SourceState.OBSERVED_ONLY) {
            throw new IllegalArgumentException(
                    "Explicit lifecycle evidence must assert ACTIVE or RESOLVED state");
        }
        LinkedHashSet<String> fingerprints = new LinkedHashSet<>(
                Objects.requireNonNull(observationFingerprints, "observationFingerprints"));
        if (fingerprints.isEmpty() || fingerprints.stream().anyMatch(String::isBlank)) {
            throw new IllegalArgumentException("At least one observation fingerprint is required");
        }
        this.observationFingerprints = Collections.unmodifiableSet(fingerprints);
    }

    public static CanonicalFindingState from(WazuhObservation observation) {
        Objects.requireNonNull(observation, "observation");
        boolean explicit = observation.evidenceCapabilities().explicitFindingLifecycle();
        return new CanonicalFindingState(
                observation.canonicalFindingIdentity(),
                observation.detectedAt(),
                observation.detectedAt(),
                explicit ? observation.evidenceAt() : observation.detectedAt(),
                explicit ? sourceState(observation.findingStatus()) : SourceState.OBSERVED_ONLY,
                explicit,
                Set.of(observation.observationFingerprint())
        );
    }

    /**
     * Returns a new state containing the supplied observation.
     *
     * <p>An already-seen immutable observation fingerprint is idempotent. A different canonical
     * finding identity is rejected. For explicit lifecycle evidence, the newest evidence timestamp
     * wins; ACTIVE wins a same-timestamp ACTIVE/RESOLVED conflict conservatively.</p>
     */
    public CanonicalFindingState observe(WazuhObservation observation) {
        Objects.requireNonNull(observation, "observation");
        CanonicalFindingIdentity candidateIdentity = observation.canonicalFindingIdentity();
        if (!identity.equals(candidateIdentity)) {
            throw new IllegalArgumentException(
                    "Observation belongs to a different canonical finding identity");
        }
        boolean candidateExplicit = observation.evidenceCapabilities().explicitFindingLifecycle();
        if (candidateExplicit != explicitLifecycle) {
            throw new IllegalArgumentException(
                    "Cannot mix observation-only and explicit lifecycle evidence in one finding state");
        }
        if (observationFingerprints.contains(observation.observationFingerprint())) {
            return this;
        }

        Instant nextFirstObservedAt = observation.detectedAt().isBefore(firstObservedAt)
                ? observation.detectedAt() : firstObservedAt;
        Instant nextLastObservedAt = observation.detectedAt().isAfter(lastObservedAt)
                ? observation.detectedAt() : lastObservedAt;
        Instant candidateEvidenceAt = explicitLifecycle
                ? observation.evidenceAt() : observation.detectedAt();
        Instant nextStateEvidenceAt = stateEvidenceAt;
        SourceState nextSourceState = sourceState;

        int evidenceOrder = candidateEvidenceAt.compareTo(stateEvidenceAt);
        if (evidenceOrder > 0) {
            nextStateEvidenceAt = candidateEvidenceAt;
            nextSourceState = explicitLifecycle
                    ? sourceState(observation.findingStatus()) : SourceState.OBSERVED_ONLY;
        } else if (evidenceOrder == 0 && explicitLifecycle) {
            SourceState candidateState = sourceState(observation.findingStatus());
            if (candidateState == SourceState.ACTIVE || sourceState == SourceState.ACTIVE) {
                nextSourceState = SourceState.ACTIVE;
            } else {
                nextSourceState = SourceState.RESOLVED;
            }
        }

        LinkedHashSet<String> nextFingerprints = new LinkedHashSet<>(observationFingerprints);
        nextFingerprints.add(observation.observationFingerprint());
        return new CanonicalFindingState(
                identity,
                nextFirstObservedAt,
                nextLastObservedAt,
                nextStateEvidenceAt,
                nextSourceState,
                explicitLifecycle,
                nextFingerprints
        );
    }

    public CanonicalFindingIdentity identity() {
        return identity;
    }

    public Instant firstObservedAt() {
        return firstObservedAt;
    }

    public Instant lastObservedAt() {
        return lastObservedAt;
    }

    public Instant stateEvidenceAt() {
        return stateEvidenceAt;
    }

    public SourceState sourceState() {
        return sourceState;
    }

    public boolean explicitLifecycle() {
        return explicitLifecycle;
    }

    public long observationCount() {
        return observationFingerprints.size();
    }

    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("identity", identity.toMap());
        output.put("firstObservedAt", firstObservedAt.toString());
        output.put("lastObservedAt", lastObservedAt.toString());
        output.put("stateEvidenceAt", stateEvidenceAt.toString());
        output.put("sourceState", sourceState.name());
        output.put("explicitLifecycle", explicitLifecycle);
        output.put("observationCount", observationCount());
        return output;
    }

    private static SourceState sourceState(FindingStatus status) {
        return status == FindingStatus.RESOLVED ? SourceState.RESOLVED : SourceState.ACTIVE;
    }
}
