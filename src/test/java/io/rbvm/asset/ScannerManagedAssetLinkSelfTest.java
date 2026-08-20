package io.rbvm.asset;

import io.rbvm.asset.ScannerManagedAssetLink.ChangeDraft;
import io.rbvm.asset.ScannerManagedAssetLink.LinkMethod;
import io.rbvm.asset.ScannerManagedAssetLink.LinkStatus;

import java.time.Instant;
import java.util.UUID;

public final class ScannerManagedAssetLinkSelfTest {
    private ScannerManagedAssetLinkSelfTest() {
    }

    public static void main(String[] args) {
        validatesExplicitStates();
        distinguishesAuditMetadataFromCustomerState();
        hashesCanonicalCustomerStateDeterministically();
        distinguishesMissingScannerFromNeverLinked();
        System.out.println("ScannerManagedAssetLinkSelfTest: PASS");
    }

    private static void validatesExplicitStates() {
        UUID managed = UUID.fromString("10000000-0000-0000-0000-000000000001");
        ChangeDraft linked = ChangeDraft.linked(managed, "operator-a", "confirmed in CMDB");
        assert linked.linkStatus() == LinkStatus.LINKED;
        assert managed.equals(linked.managedAssetId());

        ChangeDraft unlinked = ChangeDraft.unlinked("operator-a", "customer removed mapping");
        assert unlinked.linkStatus() == LinkStatus.UNLINKED;
        assert unlinked.managedAssetId() == null;

        assertThrows(() -> new ChangeDraft(LinkStatus.LINKED, null, "operator", ""));
        assertThrows(() -> new ChangeDraft(LinkStatus.UNLINKED, managed, "operator", ""));
    }

    private static void distinguishesAuditMetadataFromCustomerState() {
        UUID event = UUID.fromString("20000000-0000-0000-0000-000000000001");
        UUID scanner = UUID.fromString("30000000-0000-0000-0000-000000000001");
        UUID managed = UUID.fromString("40000000-0000-0000-0000-000000000001");
        String sha = ScannerManagedAssetLink.evidenceSha256(scanner, 1, LinkStatus.LINKED, managed);
        ScannerManagedAssetLink current = new ScannerManagedAssetLink(
                event,
                scanner,
                1,
                LinkStatus.LINKED,
                managed,
                LinkMethod.CUSTOMER_CONFIRMED,
                sha,
                "operator-a",
                "first note",
                Instant.parse("2026-08-20T10:00:00Z")
        );

        assert current.sameCustomerState(ChangeDraft.linked(managed, "operator-b", "different note"));
        UUID otherManaged = UUID.fromString("40000000-0000-0000-0000-000000000002");
        assert !current.sameCustomerState(ChangeDraft.linked(otherManaged, "operator-b", "different"));
        assert !current.sameCustomerState(ChangeDraft.unlinked("operator-b", "different"));
    }

    private static void hashesCanonicalCustomerStateDeterministically() {
        UUID scanner = UUID.fromString("50000000-0000-0000-0000-000000000001");
        UUID managed = UUID.fromString("60000000-0000-0000-0000-000000000001");
        String first = ScannerManagedAssetLink.evidenceSha256(scanner, 7, LinkStatus.LINKED, managed);
        String second = ScannerManagedAssetLink.evidenceSha256(scanner, 7, LinkStatus.LINKED, managed);
        String unlinked = ScannerManagedAssetLink.evidenceSha256(scanner, 8, LinkStatus.UNLINKED, null);
        assert first.equals(second);
        assert first.matches("[a-f0-9]{64}");
        assert !first.equals(unlinked);
    }

    private static void distinguishesMissingScannerFromNeverLinked() {
        ScannerManagedAssetLinkRegistry.CurrentLookup missing =
                new ScannerManagedAssetLinkRegistry.CurrentLookup(false, null);
        ScannerManagedAssetLinkRegistry.CurrentLookup neverLinked =
                new ScannerManagedAssetLinkRegistry.CurrentLookup(true, null);
        assert !missing.scannerAssetExists();
        assert neverLinked.scannerAssetExists();
        assert neverLinked.currentOptional().isEmpty();
    }

    private static void assertThrows(Runnable runnable) {
        boolean thrown = false;
        try {
            runnable.run();
        } catch (IllegalArgumentException expected) {
            thrown = true;
        }
        assert thrown;
    }
}
