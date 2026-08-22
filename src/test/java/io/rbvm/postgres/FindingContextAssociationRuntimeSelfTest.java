package io.rbvm.postgres;

import java.sql.SQLException;

public final class FindingContextAssociationRuntimeSelfTest {
    private FindingContextAssociationRuntimeSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        JdbcConnectionFactory neverOpen = () -> {
            throw new SQLException("runtime capability construction must not open a connection");
        };

        FindingContextAssociationRuntime disabled =
                FindingContextAssociationRuntime.forSchema(neverOpen, 20);
        assert !disabled.enabled();
        assert disabled.reachabilityScopeLinks().isEmpty();
        assert disabled.businessServiceLinks().isEmpty();

        FindingContextAssociationRuntime enabled =
                FindingContextAssociationRuntime.forSchema(neverOpen, 21);
        assert enabled.enabled();
        assert enabled.reachabilityScopeLinks().isPresent();
        assert enabled.businessServiceLinks().isPresent();
        assert enabled.reachabilityScopeLinks().get()
                instanceof PostgresFindingReachabilityScopeLinkRegistry;
        assert enabled.businessServiceLinks().get()
                instanceof PostgresFindingBusinessServiceLinkRegistry;

        boolean partialRejected = false;
        try {
            new FindingContextAssociationRuntime(
                    enabled.reachabilityScopeLinks(),
                    java.util.Optional.empty()
            );
        } catch (IllegalArgumentException expected) {
            partialRejected = true;
        }
        assert partialRejected;

        System.out.println("FindingContextAssociationRuntimeSelfTest: PASS");
    }
}
