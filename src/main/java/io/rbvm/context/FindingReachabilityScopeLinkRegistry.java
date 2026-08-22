package io.rbvm.context;

import io.rbvm.context.FindingReachabilityScopeLink.ChangeDraft;
import io.rbvm.context.FindingReachabilityScopeLink.OriginScope;
import io.rbvm.context.FindingReachabilityScopeLink.TransportProtocol;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Durable append-only registry for explicit Finding-to-reachability-scope decisions. */
public interface FindingReachabilityScopeLinkRegistry {
    /**
     * Append the desired state for the exact logical scope carried by {@code nextState}.
     * expectedRevision=0 means that scope has no recorded decision for the Finding.
     */
    MutationResult revise(UUID findingId, int expectedRevision, ChangeDraft nextState)
            throws IOException;

    /** Distinguishes a missing Finding from an existing Finding with no history for this scope. */
    CurrentLookup current(
            UUID findingId,
            OriginScope originScope,
            String originLabel,
            TransportProtocol transportProtocol,
            Integer targetPort
    ) throws IOException;

    /** Immutable newest-first history for one exact scope. */
    Optional<HistoryPage> history(
            UUID findingId,
            OriginScope originScope,
            String originLabel,
            TransportProtocol transportProtocol,
            Integer targetPort,
            int limit,
            Integer beforeRevision
    ) throws IOException;

    /** Current explicit decisions for one Finding, ordered by link-event UUID for stable pagination. */
    Optional<CurrentPage> listCurrent(UUID findingId, int limit, UUID afterEventId)
            throws IOException;

    enum MutationStatus {
        UPDATED,
        REPLAYED,
        FINDING_NOT_FOUND,
        REVISION_CONFLICT
    }

    record CurrentLookup(boolean findingExists, FindingReachabilityScopeLink current) {
        public CurrentLookup {
            if (!findingExists && current != null) {
                throw new IllegalArgumentException("missing Finding cannot have association state");
            }
        }

        public Optional<FindingReachabilityScopeLink> currentOptional() {
            return Optional.ofNullable(current);
        }
    }

    record MutationResult(MutationStatus status, FindingReachabilityScopeLink current) {
        public MutationResult {
            Objects.requireNonNull(status, "status");
            if ((status == MutationStatus.UPDATED || status == MutationStatus.REPLAYED)
                    && current == null) {
                throw new IllegalArgumentException(status + " requires current state");
            }
        }
    }

    record HistoryPage(
            UUID findingId,
            String scopeKey,
            List<FindingReachabilityScopeLink> events,
            Integer nextBeforeRevision
    ) {
        public HistoryPage {
            Objects.requireNonNull(findingId, "findingId");
            Objects.requireNonNull(scopeKey, "scopeKey");
            events = List.copyOf(Objects.requireNonNull(events, "events"));
            for (FindingReachabilityScopeLink event : events) {
                if (!findingId.equals(event.findingId()) || !scopeKey.equals(event.scopeKey())) {
                    throw new IllegalArgumentException("history contains another Finding or scope");
                }
            }
            if (nextBeforeRevision != null && nextBeforeRevision < 1) {
                throw new IllegalArgumentException("nextBeforeRevision must be positive");
            }
        }
    }

    record CurrentPage(
            UUID findingId,
            List<FindingReachabilityScopeLink> links,
            UUID nextAfterEventId
    ) {
        public CurrentPage {
            Objects.requireNonNull(findingId, "findingId");
            links = List.copyOf(Objects.requireNonNull(links, "links"));
            for (FindingReachabilityScopeLink link : links) {
                if (!findingId.equals(link.findingId())) {
                    throw new IllegalArgumentException("page contains another Finding");
                }
            }
        }
    }
}
