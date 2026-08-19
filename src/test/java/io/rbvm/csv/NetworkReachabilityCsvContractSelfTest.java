package io.rbvm.csv;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class NetworkReachabilityCsvContractSelfTest {
    private static final String SHA_A = "a".repeat(64);
    private static final String SHA_B = "b".repeat(64);

    private NetworkReachabilityCsvContractSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        parsesScopedReachabilityEvidence();
        matchesCanonicalV1AndV2AssetIdentityNormalization();
        validatesTransportEndpointSemantics();
        acceptsBomAndColumnReordering();
        deduplicatesExactObservationReplay();
        quarantinesConflictingObservationIdentity();
        quarantinesInvalidVocabularyAndProvenance();
        rejectsMissingContractHeader();
        keepsReachabilityEvidenceIndependentFromRiskDecisions();
        System.out.println("NetworkReachabilityCsvContractSelfTest: PASS");
    }

    private static void parsesScopedReachabilityEvidence() throws Exception {
        String csv = headers()
                + "wazuh-primary,SOURCE_NAME_ONLY,web-01,,INTERNET,public-internet,TCP,443,https,REACHABLE,ACTIVE_PROBE,external-probe,2026-08-19T10:00:00Z," + SHA_A + "\r\n"
                + "wazuh-v2,SOURCE_STABLE_ID,db-display,agent-db-02,INTERNAL_ENTERPRISE,corp-users,TCP,5432,postgresql,NOT_REACHABLE,FIREWALL_POLICY,fw-policy-export,2026-08-19T10:00:00Z," + SHA_B + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,router-01,,LOCAL_SEGMENT,branch-12,ICMP,,icmp,UNKNOWN,PASSIVE_OBSERVATION,network-sensor,2026-08-19T10:00:00Z," + SHA_A + "\r\n";
        List<NetworkReachabilityCsvEvidence> evidence = new ArrayList<>();
        NetworkReachabilityCsvAnalysisReport report = analyze(csv, evidence);

        assert report.contractId().equals(NetworkReachabilityCsvContract.ID);
        assert report.semantics().equals(NetworkReachabilityCsvContract.SEMANTICS);
        assert report.acceptedRows() == 3;
        assert report.quarantinedRows() == 0;
        assert report.originScopeDistribution().get("INTERNET") == 1;
        assert report.protocolDistribution().get("TCP") == 2;
        assert report.protocolDistribution().get("ICMP") == 1;
        assert report.reachabilityStatusDistribution().get("REACHABLE") == 1;
        assert report.reachabilityStatusDistribution().get("NOT_REACHABLE") == 1;
        assert report.reachabilityStatusDistribution().get("UNKNOWN") == 1;
        assert evidence.get(0).targetPort() == 443;
        assert evidence.get(2).targetPort() == null;
        assert evidence.get(0).evidenceObservedAt().equals(Instant.parse("2026-08-19T10:00:00Z"));
    }

    private static void matchesCanonicalV1AndV2AssetIdentityNormalization() throws Exception {
        List<NetworkReachabilityCsvEvidence> evidence = new ArrayList<>();
        analyze(headers()
                + "wazuh-primary,SOURCE_NAME_ONLY,  WEB-０１  ,,INTERNET,internet,TCP,443,https,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T11:00:00Z," + SHA_A + "\r\n"
                + "wazuh-v2,SOURCE_STABLE_ID,Display Name,  AGENT-００７  ,INTERNAL_ENTERPRISE,corp,TCP,22,ssh,REACHABLE,CONTROL_PLANE,routing-snapshot,2026-08-19T11:00:00Z," + SHA_A + "\r\n",
                evidence);
        assert evidence.get(0).normalizedAssetIdentityKey().equals("web-01");
        assert evidence.get(1).normalizedAssetIdentityKey().equals("agent-007");
    }

    private static void validatesTransportEndpointSemantics() throws Exception {
        String csv = headers()
                + "wazuh-primary,SOURCE_NAME_ONLY,web-01,,INTERNET,internet,TCP,,https,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T12:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-02,,INTERNET,internet,UDP,70000,dns,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T12:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-03,,INTERNET,internet,ICMP,443,icmp,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T12:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-04,,INTERNET,internet,OTHER,,custom,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T12:00:00Z," + SHA_A + "\r\n";
        NetworkReachabilityCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 1;
        assert report.quarantinedRows() == 3;
        assert report.issueSamples().stream()
                .filter(issue -> issue.code().equals("INVALID_TARGET_PORT")).count() == 3;
    }

    private static void acceptsBomAndColumnReordering() throws Exception {
        String csv = "\uFEFFAsset_Name,Asset_Source_ID,Asset_Identity_Basis,Source_Profile_Key,Origin_Label,Origin_Scope,Target_Service,Target_Port,Transport_Protocol,Reachability_Method,Reachability_Status,Evidence_Observed_At,Evidence_Source_SHA256,Evidence_Source\r\n"
                + "web-02,,SOURCE_NAME_ONLY,wazuh-primary,public-internet,INTERNET,https,443,TCP,CLOUD_CONFIGURATION,REACHABLE,2026-08-19T13:00:00Z," + SHA_A + ",cloud-inventory\r\n";
        NetworkReachabilityCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 1;
        assert report.reachabilityMethodDistribution().get("CLOUD_CONFIGURATION") == 1;
    }

    private static void deduplicatesExactObservationReplay() throws Exception {
        String row = "wazuh-primary,SOURCE_NAME_ONLY,web-03,,INTERNET,internet,TCP,443,https,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T14:00:00Z," + SHA_A + "\r\n";
        NetworkReachabilityCsvAnalysisReport report = analyze(headers() + row + row, new ArrayList<>());
        assert report.logicalRows() == 2;
        assert report.acceptedRows() == 1;
        assert report.deduplicatedRows() == 1;
        assert report.quarantinedRows() == 0;
    }

    private static void quarantinesConflictingObservationIdentity() throws Exception {
        String csv = headers()
                + "wazuh-primary,SOURCE_NAME_ONLY,WEB-04,,INTERNET,public-internet,TCP,443,https,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T15:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-04,,INTERNET,public-internet,TCP,443,https,NOT_REACHABLE,ACTIVE_PROBE,probe,2026-08-19T15:00:00Z," + SHA_B + "\r\n";
        NetworkReachabilityCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 1;
        assert report.quarantinedRows() == 1;
        assert report.issueSamples().stream()
                .anyMatch(issue -> issue.code().equals("CONFLICTING_NETWORK_REACHABILITY_OBSERVATION"));
    }

    private static void quarantinesInvalidVocabularyAndProvenance() throws Exception {
        String csv = headers()
                + "wazuh-primary,SOURCE_NAME_ONLY,web-05,agent-05,INTERNET,internet,TCP,443,https,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T16:00:00Z," + SHA_A + "\r\n"
                + "wazuh-v2,SOURCE_STABLE_ID,web-06,,INTERNET,internet,TCP,443,https,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T16:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-07,,PUBLIC,internet,TCP,443,https,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T16:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-08,,INTERNET,internet,SCTP,,custom,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T16:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-09,,INTERNET,internet,TCP,443,https,OPEN,ACTIVE_PROBE,probe,2026-08-19T16:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-10,,INTERNET,internet,TCP,443,https,REACHABLE,SCAN,probe,2026-08-19T16:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-11,,INTERNET,internet,TCP,443,https,REACHABLE,ACTIVE_PROBE,probe,2026-08-19," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-12,,INTERNET,internet,TCP,443,https,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T16:00:00Z,ABC\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-13,,INTERNET,internet,TCP,443,,REACHABLE,ACTIVE_PROBE,probe,2026-08-19T16:00:00Z," + SHA_A + "\r\n";
        NetworkReachabilityCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 0;
        assert report.quarantinedRows() == 9;
        assert report.issueSamples().stream().filter(issue -> issue.code().equals("INVALID_ASSET_IDENTITY")).count() == 2;
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_ORIGIN_SCOPE"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_TRANSPORT_PROTOCOL"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_REACHABILITY_STATUS"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_REACHABILITY_METHOD"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_EVIDENCE_OBSERVED_AT"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_EVIDENCE_SOURCE_SHA256"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("MISSING_REQUIRED_VALUE"));
    }

    private static void rejectsMissingContractHeader() throws Exception {
        String csv = "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Origin_Scope,Origin_Label,Transport_Protocol,Target_Port,Target_Service,Reachability_Status,Reachability_Method,Evidence_Source,Evidence_Observed_At\r\n";
        boolean rejected = false;
        try {
            analyze(csv, new ArrayList<>());
        } catch (CsvContractException expected) {
            rejected = expected.getMessage().contains("Evidence_Source_SHA256");
        }
        assert rejected;
    }

    private static void keepsReachabilityEvidenceIndependentFromRiskDecisions() throws Exception {
        List<NetworkReachabilityCsvEvidence> evidence = new ArrayList<>();
        analyze(headers()
                + "wazuh-primary,SOURCE_NAME_ONLY,web-14,,INTERNET,public-internet,TCP,443,https,NOT_REACHABLE,FIREWALL_POLICY,fw-export,2026-08-19T17:00:00Z," + SHA_A + "\r\n",
                evidence);
        NetworkReachabilityCsvEvidence item = evidence.get(0);
        assert item.reachabilityStatus() == NetworkReachabilityCsvEvidence.ReachabilityStatus.NOT_REACHABLE;
        String source = Files.readString(Path.of("src/main/java/io/rbvm/csv/NetworkReachabilityCsvEvidence.java"));
        assert !source.contains("riskScore");
        assert !source.contains("priorityTier");
        assert !source.contains("slaDays");
        assert !source.contains("businessCriticality");
        assert !source.contains("cvssBaseScore");
        assert !source.contains("epssProbability");
        assert !source.contains("knownExploited");
    }

    private static NetworkReachabilityCsvAnalysisReport analyze(
            String csv,
            List<NetworkReachabilityCsvEvidence> evidence
    ) throws Exception {
        Path file = Files.createTempFile("network-reachability-csv-", ".csv");
        try {
            Files.writeString(file, csv, StandardCharsets.UTF_8);
            return new NetworkReachabilityCsvAnalyzer().analyze(file, 10, evidence::add);
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static String headers() {
        return "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Origin_Scope,Origin_Label,Transport_Protocol,Target_Port,Target_Service,Reachability_Status,Reachability_Method,Evidence_Source,Evidence_Observed_At,Evidence_Source_SHA256\r\n";
    }
}
