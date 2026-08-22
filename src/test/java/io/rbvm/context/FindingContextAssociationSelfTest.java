package io.rbvm.context;

import io.rbvm.context.FindingBusinessServiceLink.ChangeDraft;
import io.rbvm.context.FindingBusinessServiceLink.LinkStatus;
import io.rbvm.context.FindingReachabilityScopeLink.OriginScope;
import io.rbvm.context.FindingReachabilityScopeLink.TransportProtocol;

import java.time.Instant;
import java.util.UUID;

public final class FindingContextAssociationSelfTest {
    private static final UUID FINDING_ID = UUID.fromString("10000000-0000-0000-0000-000000000001");

    private FindingContextAssociationSelfTest() {
    }

    public static void main(String[] args) {
        reachabilityScopeIsNormalizedAndHasStableEvidenceIdentity();
        reachabilityNeverAssessedAndExplicitUnlinkRemainDistinctByContract();
        businessServiceIsNormalizedAndAuditMetadataDoesNotChangeCustomerState();
        invalidReachabilityScopesAreRejected();
        System.out.println("FindingContextAssociationSelfTest: PASS");
    }

    private static void reachabilityScopeIsNormalizedAndHasStableEvidenceIdentity() {
        String firstSha = FindingReachabilityScopeLink.evidenceSha256(
                FINDING_ID,
                1,
                FindingReachabilityScopeLink.LinkStatus.LINKED,
                OriginScope.INTERNET,
                "  Edge Probe  ",
                TransportProtocol.TCP,
                443
        );
        String replaySha = FindingReachabilityScopeLink.evidenceSha256(
                FINDING_ID,
                1,
                FindingReachabilityScopeLink.LinkStatus.LINKED,
                OriginScope.INTERNET,
                "edge probe",
                TransportProtocol.TCP,
                443
        );
        assert firstSha.equals(replaySha);

        FindingReachabilityScopeLink link = new FindingReachabilityScopeLink(
                UUID.fromString("20000000-0000-0000-0000-000000000001"),
                FINDING_ID,
                1,
                FindingReachabilityScopeLink.LinkStatus.LINKED,
                OriginScope.INTERNET,
                "EDGE PROBE",
                TransportProtocol.TCP,
                443,
                FindingReachabilityScopeLink.LinkMethod.CUSTOMER_CONFIRMED,
                firstSha,
                "analyst@example.test",
                "Confirmed vulnerable web component serves this endpoint",
                Instant.parse("2026-08-22T00:00:00Z")
        );
        assert link.originLabel().equals("edge probe");
        assert link.scopeKey().equals("INTERNET|10:edge probe|TCP|443");
        assert link.sameCustomerState(FindingReachabilityScopeLink.ChangeDraft.linked(
                OriginScope.INTERNET,
                " edge probe ",
                TransportProtocol.TCP,
                443,
                "different-actor@example.test",
                "Different audit note"
        ));
    }

    private static void reachabilityNeverAssessedAndExplicitUnlinkRemainDistinctByContract() {
        String linked = FindingReachabilityScopeLink.evidenceSha256(
                FINDING_ID,
                1,
                FindingReachabilityScopeLink.LinkStatus.LINKED,
                OriginScope.LOCAL_SEGMENT,
                "segment-a",
                TransportProtocol.UDP,
                53
        );
        String unlinked = FindingReachabilityScopeLink.evidenceSha256(
                FINDING_ID,
                2,
                FindingReachabilityScopeLink.LinkStatus.UNLINKED,
                OriginScope.LOCAL_SEGMENT,
                "segment-a",
                TransportProtocol.UDP,
                53
        );
        assert !linked.equals(unlinked);
        assert FindingReachabilityScopeLink.LinkStatus.UNLINKED
                != FindingReachabilityScopeLink.LinkStatus.LINKED;
    }

    private static void businessServiceIsNormalizedAndAuditMetadataDoesNotChangeCustomerState() {
        String sha = FindingBusinessServiceLink.evidenceSha256(
                FINDING_ID,
                1,
                LinkStatus.LINKED,
                "  Payments  "
        );
        assert sha.equals(FindingBusinessServiceLink.evidenceSha256(
                FINDING_ID,
                1,
                LinkStatus.LINKED,
                "payments"
        ));

        FindingBusinessServiceLink link = new FindingBusinessServiceLink(
                UUID.fromString("30000000-0000-0000-0000-000000000001"),
                FINDING_ID,
                1,
                LinkStatus.LINKED,
                "PAYMENTS",
                FindingBusinessServiceLink.LinkMethod.CUSTOMER_CONFIRMED,
                sha,
                "service-owner@example.test",
                "Finding affects the Payments service",
                Instant.parse("2026-08-22T00:00:00Z")
        );
        assert link.businessService().equals("payments");
        ChangeDraft replay = ChangeDraft.linked(
                " payments ",
                "other-actor@example.test",
                "Audit metadata is intentionally not customer state"
        );
        assert link.sameCustomerState(replay);
        assert !link.sameCustomerState(ChangeDraft.unlinked(
                "payments",
                "other-actor@example.test",
                "Explicitly remove the association"
        ));
    }

    private static void invalidReachabilityScopesAreRejected() {
        expectFailure(() -> FindingReachabilityScopeLink.ChangeDraft.linked(
                OriginScope.INTERNET,
                "probe",
                TransportProtocol.TCP,
                null,
                "actor",
                "missing TCP port"
        ));
        expectFailure(() -> FindingReachabilityScopeLink.ChangeDraft.linked(
                OriginScope.LOCAL_SEGMENT,
                "probe",
                TransportProtocol.ICMP,
                443,
                "actor",
                "ICMP cannot have a port"
        ));
        expectFailure(() -> FindingReachabilityScopeLink.ChangeDraft.linked(
                OriginScope.INTERNET,
                "   ",
                TransportProtocol.TCP,
                443,
                "actor",
                "blank origin label"
        ));
    }

    private static void expectFailure(Runnable runnable) {
        boolean failed = false;
        try {
            runnable.run();
        } catch (IllegalArgumentException | NullPointerException expected) {
            failed = true;
        }
        assert failed;
    }
}
