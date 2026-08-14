package io.rbvm.domain;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class DomainCatalogSelfTest {
    private DomainCatalogSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        materializesCanonicalEntitiesAndUsesEventTime();
        deduplicatesAcrossImportsAndReplaysOneImport();
        malformedCsvDoesNotPartiallyCommit();
        queriesAndPaginatesCases();
        enforcesWorkflowAndIdempotency();
        closesAndReopensOnlyFromExplicitV2Evidence();
        materializesVulnerabilityPriorityIntelligence();
        System.out.println("DomainCatalogSelfTest: PASS");
    }

    private static void materializesCanonicalEntitiesAndUsesEventTime() throws Exception {
        InMemoryDomainCatalog catalog = catalog();
        Path csv = csv(domainRows());
        try {
            DomainMaterializationResult result = catalog.materialize(
                    UUID.fromString("600baf81-0a94-40c6-a5c8-d77c72b91384"),
                    csv,
                    "profile-a"
            );
            assert result.acceptedObservations() == 4;
            assert result.insertedObservations() == 4;
            assert result.duplicateObservations() == 0;
            assert result.newAssets() == 1;
            assert result.newVulnerabilities() == 1;
            assert result.newComponents() == 2;
            assert result.newExposures() == 2;
            assert result.newCases() == 1;

            CatalogSnapshot snapshot = catalog.snapshot();
            assert snapshot.materializedImports() == 1;
            assert snapshot.observations() == 4;
            assert snapshot.importObservationLinks() == 4;
            assert snapshot.assets() == 1;
            assert snapshot.vulnerabilities() == 1;
            assert snapshot.components() == 2;
            assert snapshot.exposures() == 2;
            assert snapshot.cases() == 1;
            assert snapshot.openCases() == 1;
            assert snapshot.autoClosedCases() == 0;
            assert snapshot.exposuresWithSeverityChanges() == 1;
            assert snapshot.exposuresWithTimestampConflicts() == 1;
            assert snapshot.currentCaseSeverityDistribution().get("CRITICAL") == 1;

            Map<String, Object> caseView = catalog.casePreview(1).get(0);
            assert caseView.get("currentSeverity").equals("CRITICAL");
            assert caseView.get("status").equals("OPEN");
            assert caseView.get("firstObservedAt").equals("2026-07-01T10:00:00Z");
            assert caseView.get("lastObservedAt").equals("2026-07-03T10:00:00Z");
            assert caseView.get("exposureCount").equals(2);
            assert caseView.get("closurePolicy").equals("POSITIVE_ONLY_NO_AUTO_CLOSE");
        } finally {
            Files.deleteIfExists(csv);
        }
    }

    private static void deduplicatesAcrossImportsAndReplaysOneImport() throws Exception {
        InMemoryDomainCatalog catalog = catalog();
        Path csv = csv(domainRows());
        UUID firstId = UUID.fromString("600baf81-0a94-40c6-a5c8-d77c72b91384");
        UUID secondId = UUID.fromString("d266b1c0-2222-4d50-ab96-adf667fb428f");
        try {
            catalog.materialize(firstId, csv, "profile-a");
            DomainMaterializationResult second = catalog.materialize(secondId, csv, "profile-a");
            assert second.acceptedObservations() == 4;
            assert second.insertedObservations() == 0;
            assert second.duplicateObservations() == 4;
            assert catalog.snapshot().observations() == 4;
            assert catalog.snapshot().importObservationLinks() == 8;

            DomainMaterializationResult replay = catalog.materialize(secondId, csv, "profile-a");
            assert replay.replayed();
            assert catalog.snapshot().materializedImports() == 2;
            assert catalog.snapshot().importObservationLinks() == 8;
        } finally {
            Files.deleteIfExists(csv);
        }
    }

    private static void malformedCsvDoesNotPartiallyCommit() throws Exception {
        InMemoryDomainCatalog catalog = catalog();
        String malformed = headers()
                + "agent-a,CVE-2025-1234,High,description,pkg-a,https://example.test/1,Ubuntu,2026-07-01T10:00:00Z\r\n"
                + "agent-b,CVE-2025-5678,Medium,\"unterminated";
        Path csv = csv(malformed);
        try {
            boolean rejected = false;
            try {
                catalog.materialize(UUID.randomUUID(), csv, "profile-a");
            } catch (RuntimeException expected) {
                rejected = expected.getMessage().contains("quoted field");
            }
            assert rejected;
            assert catalog.snapshot().materializedImports() == 0;
            assert catalog.snapshot().observations() == 0;
            assert catalog.snapshot().assets() == 0;
            assert catalog.snapshot().cases() == 0;
        } finally {
            Files.deleteIfExists(csv);
        }
    }

    private static void queriesAndPaginatesCases() throws Exception {
        InMemoryDomainCatalog catalog = catalog();
        String rows = headers()
                + "agent-a,CVE-2025-1001,Critical,description,pkg-a,https://example.test/1,Ubuntu,2026-07-03T10:00:00Z\r\n"
                + "agent-b,CVE-2025-1002,High,description,pkg-b,https://example.test/2,Debian,2026-07-02T10:00:00Z\r\n"
                + "agent-c,CVE-2025-1003,Medium,description,pkg-c,https://example.test/3,Ubuntu,2026-07-01T10:00:00Z\r\n";
        Path csv = csv(rows);
        try {
            catalog.materialize(UUID.randomUUID(), csv, "profile-a");
            CasePage first = catalog.queryCases(CaseQuery.firstPage(1));
            assert first.cases().size() == 1;
            assert first.cases().get(0).get("currentSeverity").equals("CRITICAL");
            assert first.nextCursor() != null;

            CasePage second = catalog.queryCases(new CaseQuery(
                    1,
                    first.nextCursor(),
                    Set.of(),
                    Set.of(),
                    null,
                    null
            ));
            assert second.cases().get(0).get("currentSeverity").equals("HIGH");

            CasePage filtered = catalog.queryCases(new CaseQuery(
                    20,
                    null,
                    Set.of(io.rbvm.csv.CsvSeverity.MEDIUM),
                    Set.of(CaseStatus.OPEN),
                    "1003",
                    "agent-c"
            ));
            assert filtered.cases().size() == 1;
            assert filtered.cases().get(0).get("cveId").equals("CVE-2025-1003");
            assert filtered.cases().get(0).get("assetName").equals("agent-c");
        } finally {
            Files.deleteIfExists(csv);
        }
    }

    private static void enforcesWorkflowAndIdempotency() throws Exception {
        InMemoryDomainCatalog catalog = catalog();
        Path csv = csv(domainRows());
        try {
            catalog.materialize(UUID.randomUUID(), csv, "profile-a");
            CasePage initial = catalog.queryCases(CaseQuery.firstPage(1));
            String caseId = initial.cases().get(0).get("caseId").toString();
            Instant actionTime = Instant.parse("2026-07-20T12:00:00Z");
            CaseActionCommand accept = new CaseActionCommand(
                    CaseActionType.ACCEPT_RISK,
                    "Approved temporary exception",
                    Instant.parse("2026-08-20T12:00:00Z"),
                    null
            );
            PreparedCaseAction prepared = catalog.prepareCaseAction(
                    1,
                    caseId,
                    accept,
                    "accept-key-0001",
                    "local-operator",
                    "UNAUTHENTICATED_LOCAL",
                    actionTime
            );
            assert !prepared.replayed();
            Map<String, Object> accepted = catalog.applyCaseEvent(prepared.event());
            assert accepted.get("status").equals("ACCEPTED_RISK");
            assert accepted.get("workflowVersion").equals(1L);
            assert accepted.get("riskAcceptedUntil").equals("2026-08-20T12:00:00Z");
            assert ((java.util.List<?>) accepted.get("auditEvents")).size() == 1;
            assert catalog.snapshot().openCases() == 0;

            PreparedCaseAction replay = catalog.prepareCaseAction(
                    99,
                    caseId,
                    accept,
                    "accept-key-0001",
                    "local-operator",
                    "UNAUTHENTICATED_LOCAL",
                    actionTime
            );
            assert replay.replayed();
            assert replay.event().eventId().equals(prepared.event().eventId());

            boolean idempotencyConflict = false;
            try {
                catalog.prepareCaseAction(
                        2,
                        caseId,
                        new CaseActionCommand(
                                CaseActionType.ACCEPT_RISK,
                                "Different request",
                                Instant.parse("2026-09-20T12:00:00Z"),
                                null
                        ),
                        "accept-key-0001",
                        "local-operator",
                        "UNAUTHENTICATED_LOCAL",
                        actionTime
                );
            } catch (CaseWorkflowConflictException expected) {
                idempotencyConflict = true;
            }
            assert idempotencyConflict;

            CaseActionCommand close = new CaseActionCommand(
                    CaseActionType.CLOSE_MANUAL,
                    "Verified remediation through change record",
                    null,
                    "CHG-2026-0042"
            );
            PreparedCaseAction closeEvent = catalog.prepareCaseAction(
                    2,
                    caseId,
                    close,
                    "close-key-0001",
                    "local-operator",
                    "UNAUTHENTICATED_LOCAL",
                    actionTime.plusSeconds(60)
            );
            Map<String, Object> closed = catalog.applyCaseEvent(closeEvent.event());
            assert closed.get("status").equals("CLOSED_MANUAL");
            assert closed.get("decisionEvidence").equals("CHG-2026-0042");

            PreparedCaseAction reopen = catalog.prepareCaseAction(
                    3,
                    caseId,
                    new CaseActionCommand(CaseActionType.REOPEN, "Evidence was revoked", null, null),
                    "reopen-key-0001",
                    "local-operator",
                    "UNAUTHENTICATED_LOCAL",
                    actionTime.plusSeconds(120)
            );
            Map<String, Object> reopened = catalog.applyCaseEvent(reopen.event());
            assert reopened.get("status").equals("OPEN");
            assert reopened.get("decisionEvidence") == null;
            assert ((java.util.List<?>) reopened.get("auditEvents")).size() == 3;
            assert catalog.snapshot().openCases() == 1;

            boolean expiredAcceptanceRejected = false;
            try {
                catalog.prepareCaseAction(
                        4,
                        caseId,
                        new CaseActionCommand(
                                CaseActionType.ACCEPT_RISK,
                                "Expired exception",
                                actionTime.minusSeconds(1),
                                null
                        ),
                        "expired-key-0001",
                        "local-operator",
                        "UNAUTHENTICATED_LOCAL",
                        actionTime
                );
            } catch (InvalidCaseActionException expected) {
                expiredAcceptanceRejected = true;
            }
            assert expiredAcceptanceRejected;
        } finally {
            Files.deleteIfExists(csv);
        }
    }

    private static void closesAndReopensOnlyFromExplicitV2Evidence() throws Exception {
        InMemoryDomainCatalog catalog = catalog();
        String header = "Agent,Agent_ID,CVE_ID,Severity,CVE_Description,Affected_Product,"
                + "Package_Version,Package_Architecture,References,OS_name,Finding_Status,"
                + "Detected_At,Resolved_At\r\n";
        String identity = "agent-name,agent-001,CVE-2026-5555,High,description,openssl,3.0.2,"
                + "amd64,https://example.test/evidence,Ubuntu,";
        Path active = csv(header + identity + "ACTIVE,2026-08-01T10:00:00Z,\r\n");
        Path absent = csv(header);
        Path resolved = csv(header + identity
                + "RESOLVED,2026-08-01T10:00:00Z,2026-08-02T10:00:00Z\r\n");
        Path reopened = csv(header + identity + "ACTIVE,2026-08-03T10:00:00Z,\r\n");
        try {
            catalog.materialize(UUID.randomUUID(), active, "v2-profile", "WAZUH_CSV_V2");
            Map<String, Object> first = catalog.casePreview(1).get(0);
            assert first.get("status").equals("OPEN");
            String caseId = first.get("caseId").toString();

            catalog.materialize(UUID.randomUUID(), absent, "v2-profile", "WAZUH_CSV_V2");
            assert catalog.casePreview(1).get(0).get("status").equals("OPEN")
                    : "absence must not close";

            catalog.materialize(UUID.randomUUID(), resolved, "v2-profile", "WAZUH_CSV_V2");
            Map<String, Object> closed = catalog.casePreview(1).get(0);
            assert closed.get("caseId").equals(caseId);
            assert closed.get("status").equals("SOURCE_RESOLVED");
            assert catalog.snapshot().autoClosedCases() == 1;
            Map<?, ?> exposure = (Map<?, ?>) ((java.util.List<?>) catalog.caseDetail(caseId)
                    .orElseThrow().get("exposures")).get(0);
            assert exposure.get("packageVersion").equals("3.0.2");
            assert exposure.get("packageArchitecture").equals("amd64");
            assert exposure.get("resolvedAt").equals("2026-08-02T10:00:00Z");

            catalog.materialize(UUID.randomUUID(), reopened, "v2-profile", "WAZUH_CSV_V2");
            assert catalog.casePreview(1).get(0).get("status").equals("OPEN");
            assert catalog.snapshot().autoClosedCases() == 0;
        } finally {
            Files.deleteIfExists(active);
            Files.deleteIfExists(absent);
            Files.deleteIfExists(resolved);
            Files.deleteIfExists(reopened);
        }
    }

    private static void materializesVulnerabilityPriorityIntelligence() throws Exception {
        InMemoryDomainCatalog catalog = catalog();
        String header = "Agent,Agent_ID,CVE_ID,Severity,CVE_Description,Affected_Product,"
                + "Package_Version,Package_Architecture,References,OS_name,Finding_Status,"
                + "Detected_At,Resolved_At,CVSS_Version,CVSS_Base_Score,CVSS_Vector,"
                + "EPSS_Probability,EPSS_Percentile,Known_Exploited,KEV_Date_Added,"
                + "KEV_Due_Date,Intel_Observed_At,Intel_Source_References\r\n";
        String row = "agent,stable-1,CVE-2026-7777,High,description,pkg,2.0,amd64,"
                + "https://example.test/cve,Ubuntu,ACTIVE,2026-08-01T00:00:00Z,,3.1,8.1,"
                + "CVSS:3.1/AV:N,0.25,0.94,true,2026-08-02,2026-08-22,"
                + "2026-08-14T00:00:00Z,https://www.cisa.gov/known-exploited-vulnerabilities-catalog\r\n";
        Path csv = csv(header + row);
        try {
            catalog.materialize(UUID.randomUUID(), csv, "intel-profile", "WAZUH_CSV_V2");
            Map<?, ?> intel = (Map<?, ?>) catalog.casePreview(1).get(0)
                    .get("vulnerabilityIntelligence");
            assert intel.get("priorityTier").equals("IMMEDIATE");
            assert intel.get("knownExploited").equals(true);
            assert intel.get("epssProbability").equals(0.25);
            assert intel.get("cvssBaseScore").equals(8.1);
            CasePage filtered = catalog.queryCases(new CaseQuery(
                    10, null, Set.of(), Set.of(), null, null,
                    Set.of(VulnerabilityPriorityTier.IMMEDIATE), true));
            assert filtered.cases().size() == 1;
            CasePage excluded = catalog.queryCases(new CaseQuery(
                    10, null, Set.of(), Set.of(), null, null,
                    Set.of(VulnerabilityPriorityTier.STANDARD), null));
            assert excluded.cases().isEmpty();
        } finally {
            Files.deleteIfExists(csv);
        }
    }

    private static InMemoryDomainCatalog catalog() {
        return new InMemoryDomainCatalog(Clock.fixed(
                Instant.parse("2026-07-20T12:00:00Z"),
                ZoneOffset.UTC
        ));
    }

    private static Path csv(String content) throws Exception {
        Path file = Files.createTempFile("rbvm-domain-", ".csv");
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return file;
    }

    private static String domainRows() {
        return headers()
                + "agent-a,CVE-2025-1234,High,description,pkg-a,https://example.test/1,Ubuntu,2026-07-02T10:00:00Z\r\n"
                + "agent-a,CVE-2025-1234,Low,description,pkg-a,https://example.test/1,Ubuntu,2026-07-01T10:00:00Z\r\n"
                + "agent-a,CVE-2025-1234,Medium,description,pkg-b,https://example.test/1,Ubuntu,2026-07-03T10:00:00Z\r\n"
                + "agent-a,CVE-2025-1234,Critical,description,pkg-a,https://example.test/1,Ubuntu,2026-07-02T10:00:00Z\r\n";
    }

    private static String headers() {
        return "Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At\r\n";
    }
}
