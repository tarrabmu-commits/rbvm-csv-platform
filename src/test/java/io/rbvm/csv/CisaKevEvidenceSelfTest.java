package io.rbvm.csv;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Map;

public final class CisaKevEvidenceSelfTest {
    private static final String SOURCE =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private static final String SHA256 =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private CisaKevEvidenceSelfTest() {
    }

    public static void main(String[] args) {
        validatesCompleteSnapshotProvenance();
        unknownMeansNoUsableCatalogEvidence();
        listedCarriesExplicitCatalogMembershipEvidence();
        notListedIsSnapshotBoundNegativeMembershipEvidence();
        rejectsInvalidIdentityAndProvenance();
        doesNotDeriveRiskPriorityOrSla();
        System.out.println("CisaKevEvidenceSelfTest: PASS");
    }

    private static void validatesCompleteSnapshotProvenance() {
        CisaKevCatalogSnapshot snapshot = snapshot();
        assert snapshot.catalogVersion().equals("2026.08.19");
        assert snapshot.source().equals(SOURCE);
        assert snapshot.sha256().equals(SHA256);
        assert snapshot.declaredCount() == 1500;
        assert snapshot.parsedCount() == 1500;
        assert snapshot.snapshotKey().equals("2026.08.19|" + SHA256);

        assertRejected(() -> new CisaKevCatalogSnapshot(
                "2026.08.19",
                SOURCE,
                Instant.parse("2026-08-19T09:30:00Z"),
                SHA256,
                1500,
                1499
        ));
    }

    private static void unknownMeansNoUsableCatalogEvidence() {
        CisaKevEvidence evidence = CisaKevEvidence.unknown("cve-2026-10001");
        assert evidence.cveId().equals("CVE-2026-10001");
        assert evidence.status() == CisaKevEvidence.Status.UNKNOWN;
        assert !evidence.hasCatalogEvidence();
        assert evidence.snapshot() == null;
        assert evidence.dateAdded() == null;
        assert evidence.dueDate() == null;
        assert evidence.ransomwareCampaignUse() == null;
        assert evidence.toMap().get("kevStatus").equals("UNKNOWN");
        assert evidence.toMap().get("kevEvidenceObserved").equals(false);
    }

    private static void listedCarriesExplicitCatalogMembershipEvidence() {
        CisaKevEvidence evidence = CisaKevEvidence.listed(
                "CVE-2026-10001",
                snapshot(),
                LocalDate.parse("2026-08-18"),
                LocalDate.parse("2026-09-01"),
                CisaKevEvidence.RansomwareCampaignUse.KNOWN
        );
        assert evidence.status() == CisaKevEvidence.Status.LISTED;
        assert evidence.hasCatalogEvidence();
        assert evidence.snapshot().catalogVersion().equals("2026.08.19");
        assert evidence.snapshot().source().equals(SOURCE);
        assert evidence.dateAdded().equals(LocalDate.parse("2026-08-18"));
        assert evidence.dueDate().equals(LocalDate.parse("2026-09-01"));
        assert evidence.ransomwareCampaignUse()
                == CisaKevEvidence.RansomwareCampaignUse.KNOWN;
        assert evidence.toMap().get("knownRansomwareCampaignUse").equals("KNOWN");
        assert evidence.toMap().get("kevCatalogSha256").equals(SHA256);
        assert evidence.toMap().get("kevCatalogCount").equals(1500);
    }

    private static void notListedIsSnapshotBoundNegativeMembershipEvidence() {
        CisaKevEvidence evidence = CisaKevEvidence.notListed(
                "CVE-2026-10002",
                snapshot()
        );
        assert evidence.status() == CisaKevEvidence.Status.NOT_LISTED;
        assert evidence.hasCatalogEvidence();
        assert evidence.snapshot().catalogVersion().equals("2026.08.19");
        assert evidence.dateAdded() == null;
        assert evidence.dueDate() == null;
        assert evidence.ransomwareCampaignUse() == null;
        Map<String, Object> map = evidence.toMap();
        assert map.get("kevStatus").equals("NOT_LISTED");
        assert map.get("kevEvidenceObserved").equals(true);
        assert map.get("kevCatalogSha256").equals(SHA256);
        assert !map.containsKey("knownExploited");
        assert !map.containsKey("exploited");
    }

    private static void rejectsInvalidIdentityAndProvenance() {
        assertRejected(() -> CisaKevEvidence.unknown("not-a-cve"));
        assertRejected(() -> new CisaKevCatalogSnapshot(
                "2026.08.19",
                "http://www.cisa.gov/kev.json",
                Instant.parse("2026-08-19T09:30:00Z"),
                SHA256,
                1500,
                1500
        ));
        assertRejected(() -> new CisaKevCatalogSnapshot(
                " ",
                SOURCE,
                Instant.parse("2026-08-19T09:30:00Z"),
                SHA256,
                1500,
                1500
        ));
        assertRejected(() -> new CisaKevCatalogSnapshot(
                "2026.08.19",
                SOURCE,
                Instant.parse("2026-08-19T09:30:00Z"),
                "bad-sha",
                1500,
                1500
        ));
        assertRejected(() -> CisaKevEvidence.listed(
                "CVE-2026-10001",
                snapshot(),
                LocalDate.parse("2026-08-18"),
                LocalDate.parse("2026-09-01"),
                null
        ));
        assertRejected(() -> CisaKevEvidence.notListed("CVE-2026-10002", null));
    }

    private static void doesNotDeriveRiskPriorityOrSla() {
        Map<String, Object> evidence = CisaKevEvidence.listed(
                "CVE-2026-10001",
                snapshot(),
                LocalDate.parse("2026-08-18"),
                LocalDate.parse("2026-09-01"),
                CisaKevEvidence.RansomwareCampaignUse.UNKNOWN
        ).toMap();
        assert !evidence.containsKey("priorityTier");
        assert !evidence.containsKey("priority");
        assert !evidence.containsKey("riskScore");
        assert !evidence.containsKey("sla");
        assert !evidence.containsKey("epss");
    }

    private static CisaKevCatalogSnapshot snapshot() {
        return new CisaKevCatalogSnapshot(
                "2026.08.19",
                SOURCE,
                Instant.parse("2026-08-19T09:30:00Z"),
                SHA256,
                1500,
                1500
        );
    }

    private static void assertRejected(Runnable operation) {
        boolean rejected = false;
        try {
            operation.run();
        } catch (IllegalArgumentException | NullPointerException expected) {
            rejected = true;
        }
        assert rejected;
    }
}
