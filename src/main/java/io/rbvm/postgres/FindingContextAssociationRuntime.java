package io.rbvm.postgres;

import io.rbvm.context.FindingBusinessServiceLinkRegistry;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry;

import java.io.IOException;
import java.time.Clock;
import java.util.Objects;
import java.util.Optional;

/** Runtime capability bundle for the explicit Finding-context association contracts introduced in V21. */
public record FindingContextAssociationRuntime(
        Optional<FindingReachabilityScopeLinkRegistry> reachabilityScopeLinks,
        Optional<FindingBusinessServiceLinkRegistry> businessServiceLinks
) {
    public static final int REQUIRED_SCHEMA_VERSION = 21;

    public FindingContextAssociationRuntime {
        reachabilityScopeLinks = Objects.requireNonNull(reachabilityScopeLinks, "reachabilityScopeLinks");
        businessServiceLinks = Objects.requireNonNull(businessServiceLinks, "businessServiceLinks");
        if (reachabilityScopeLinks.isPresent() != businessServiceLinks.isPresent()) {
            throw new IllegalArgumentException(
                    "Finding context association capabilities must be enabled or disabled together"
            );
        }
    }

    public static FindingContextAssociationRuntime disabled() {
        return new FindingContextAssociationRuntime(Optional.empty(), Optional.empty());
    }

    static FindingContextAssociationRuntime forSchema(
            JdbcConnectionFactory connections,
            int installedVersion
    ) throws IOException {
        Objects.requireNonNull(connections, "connections");
        if (installedVersion < REQUIRED_SCHEMA_VERSION) {
            return disabled();
        }
        Clock clock = Clock.systemUTC();
        return new FindingContextAssociationRuntime(
                Optional.of(new PostgresFindingReachabilityScopeLinkRegistry(
                        connections,
                        installedVersion,
                        clock
                )),
                Optional.of(new PostgresFindingBusinessServiceLinkRegistry(
                        connections,
                        installedVersion,
                        clock
                ))
        );
    }

    public boolean enabled() {
        return reachabilityScopeLinks.isPresent();
    }
}
