package io.rbvm.context;

import io.rbvm.context.FindingBusinessServiceLink.ChangeDraft;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Durable append-only registry for explicit Finding-to-business-service decisions. */
public interface FindingBusinessServiceLinkRegistry {
    /**
     * Append the desired state for the exact normalized service carried by {@code nextState}.
     * expectedRevision=0 means that service has no recorded decision for the Finding.
     */
    MutationResult revise(UUID findingId, int expectedRevision, ChangeDraft nextState)
            throws IOException;

    /** Distinguishes a missing Finding from an existing Finding with no history for this service. */
    CurrentLookup current(UUID findingId, String businessService) throws IOException;

    /** Immutable newest-first history for one exact normalized business service. */
    Optional<HistoryPage> history(
            UUID findingId,
            String businessService,
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

    record CurrentLookup(boolean findingExists, FindingBusinessServiceLink current) {
        public CurrentLookup {
            if (!findingExists && current != null) {
                throw new IllegalArgumentException("missing Finding cannot have association state");
            }
        }

        public Optional<FindingBusinessServiceLink> currentOptional() {
            return Optional.ofNullable(current);
        }
    }

    record MutationResult(MutationStatus status, FindingBusinessServiceLink current) {
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
            String businessService,
            List<FindingBusinessServiceLink> events,
            Integer nextBeforeRevision
    ) {
        public HistoryPage {
            Objects.requireNonNull(findingId, "findingId");
            Objects.requireNonNull(businessService, "businessService");
            events = List.copyOf(Objects.requireNonNull(events, "events"));
            for (FindingBusinessServiceLink event : events) {
                if (!findingId.equals(event.findingId())
                        || !businessService.equals(event.businessService())) {
                    throw new IllegalArgumentException("history contains another Finding or service");
                }
            }
            if (nextBeforeRevision != null && nextBeforeRevision < 1) {
                throw new IllegalArgumentException("nextBeforeRevision must be positive");
            }
        }
    }

    record CurrentPage(
            UUID findingId,
            List<FindingBusinessServiceLink> links,
            UUID nextAfterEventId
    ) {
        public CurrentPage {
            Objects.requireNonNull(findingId, "findingId");
            links = List.copyOf(Objects.requireNonNull(links, "links"));
            for (FindingBusinessServiceLink link : links) {
                if (!findingId.equals(link.findingId())) {
                    throw new IllegalArgumentException("page contains another Finding");
                }
            }
        }
    }
}
