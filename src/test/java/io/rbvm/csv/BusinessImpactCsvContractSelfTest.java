package io.rbvm.csv;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class BusinessImpactCsvContractSelfTest {
    private static final String SHA_A = "a".repeat(64);
    private static final String SHA_B = "b".repeat(64);

    private BusinessImpactCsvContractSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        parsesQualitativeServiceImpactEvidence();
        matchesCanonicalAssetAndServiceNormalization();
        acceptsBomAndColumnReordering();
        deduplicatesExactObservationReplay();
        quarantinesConflictingObservation();
        quarantinesInvalidVocabularyIdentityAndProvenance();
        rejectsMissingContractHeader();
        keepsImpactEvidenceIndependentFromDecisionWeights();
        System.out.println("BusinessImpactCsvContractSelfTest: PASS");
    }

    private static void parsesQualitativeServiceImpactEvidence() throws Exception {
        String csv = headers()
                + "wazuh-primary,SOURCE_NAME_ONLY,web-01,,Checkout,AVAILABILITY,SEVERE,BUSINESS_IMPACT_ANALYSIS,Checkout outage stops customer purchases,BIA-2026,2026-08-19T09:00:00Z," + SHA_A + "\r\n"
                + "wazuh-v2,SOURCE_STABLE_ID,db-display,agent-db-02,Settlement,REGULATORY,HIGH,POLICY_CLASSIFICATION,Regulated settlement records require protected processing,policy-register,2026-08-19T09:00:00Z," + SHA_B + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,safety-01,,Plant Control,SAFETY,UNKNOWN,SERVICE_OWNER_ATTESTATION,Safety consequence is under formal reassessment,service-owner,2026-08-19T09:00:00Z," + SHA_A + "\r\n";
        List<BusinessImpactCsvEvidence> evidence = new ArrayList<>();
        BusinessImpactCsvAnalysisReport report = analyze(csv, evidence);
        assert report.contractId().equals(BusinessImpactCsvContract.ID);
        assert report.semantics().equals(BusinessImpactCsvContract.SEMANTICS);
        assert report.acceptedRows() == 3;
        assert report.quarantinedRows() == 0;
        assert report.impactDimensionDistribution().get("AVAILABILITY") == 1;
        assert report.impactDimensionDistribution().get("REGULATORY") == 1;
        assert report.impactLevelDistribution().get("SEVERE") == 1;
        assert report.impactLevelDistribution().get("UNKNOWN") == 1;
        assert report.impactMethodDistribution().get("BUSINESS_IMPACT_ANALYSIS") == 1;
        assert evidence.get(0).impactObservedAt().equals(Instant.parse("2026-08-19T09:00:00Z"));
    }

    private static void matchesCanonicalAssetAndServiceNormalization() throws Exception {
        List<BusinessImpactCsvEvidence> evidence = new ArrayList<>();
        analyze(headers()
                + "wazuh-primary,SOURCE_NAME_ONLY,  WEB-０１  ,,  CHECKOUT  ,MISSION,HIGH,SERVICE_OWNER_ATTESTATION,Core purchase mission dependency,owner-register,2026-08-19T10:00:00Z," + SHA_A + "\r\n"
                + "wazuh-v2,SOURCE_STABLE_ID,Display Name,  AGENT-００７  ,Settlement,FINANCIAL,MODERATE,INCIDENT_ANALYSIS,Historical outage caused material settlement delay,incident-review,2026-08-19T10:00:00Z," + SHA_A + "\r\n",
                evidence);
        assert evidence.get(0).normalizedAssetIdentityKey().equals("web-01");
        assert evidence.get(0).normalizedBusinessService().equals("checkout");
        assert evidence.get(1).normalizedAssetIdentityKey().equals("agent-007");
    }

    private static void acceptsBomAndColumnReordering() throws Exception {
        String csv = "\uFEFFAsset_Name,Asset_Source_ID,Asset_Identity_Basis,Source_Profile_Key,Business_Service,Impact_Source,Impact_Observed_At,Impact_Source_SHA256,Impact_Dimension,Impact_Level,Impact_Method,Impact_Statement\r\n"
                + "web-02,,SOURCE_NAME_ONLY,wazuh-primary,Checkout,BIA-2026,2026-08-19T11:00:00Z," + SHA_A + ",OPERATIONAL,HIGH,BUSINESS_IMPACT_ANALYSIS,Operational disruption affects order processing\r\n";
        BusinessImpactCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 1;
        assert report.impactDimensionDistribution().get("OPERATIONAL") == 1;
    }

    private static void deduplicatesExactObservationReplay() throws Exception {
        String row = "wazuh-primary,SOURCE_NAME_ONLY,web-03,,Checkout,REPUTATIONAL,MODERATE,POLICY_CLASSIFICATION,Customer trust impact classification,policy-register,2026-08-19T12:00:00Z," + SHA_A + "\r\n";
        BusinessImpactCsvAnalysisReport report = analyze(headers() + row + row, new ArrayList<>());
        assert report.logicalRows() == 2;
        assert report.acceptedRows() == 1;
        assert report.deduplicatedRows() == 1;
        assert report.quarantinedRows() == 0;
    }

    private static void quarantinesConflictingObservation() throws Exception {
        String csv = headers()
                + "wazuh-primary,SOURCE_NAME_ONLY,WEB-04,,Checkout,AVAILABILITY,HIGH,BUSINESS_IMPACT_ANALYSIS,Outage stops purchases,BIA-2026,2026-08-19T13:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-04,,checkout,AVAILABILITY,LOW,BUSINESS_IMPACT_ANALYSIS,Outage has limited effect,BIA-2026,2026-08-19T13:00:00Z," + SHA_B + "\r\n";
        BusinessImpactCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 1;
        assert report.quarantinedRows() == 1;
        assert report.issueSamples().stream()
                .anyMatch(issue -> issue.code().equals("CONFLICTING_BUSINESS_IMPACT_OBSERVATION"));
    }

    private static void quarantinesInvalidVocabularyIdentityAndProvenance() throws Exception {
        String csv = headers()
                + "wazuh-primary,SOURCE_NAME_ONLY,web-05,agent-05,Checkout,MISSION,HIGH,BUSINESS_IMPACT_ANALYSIS,statement,BIA,2026-08-19T14:00:00Z," + SHA_A + "\r\n"
                + "wazuh-v2,SOURCE_STABLE_ID,web-06,,Checkout,MISSION,HIGH,BUSINESS_IMPACT_ANALYSIS,statement,BIA,2026-08-19T14:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-07,,Checkout,LEGAL,HIGH,BUSINESS_IMPACT_ANALYSIS,statement,BIA,2026-08-19T14:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-08,,Checkout,MISSION,CRITICAL,BUSINESS_IMPACT_ANALYSIS,statement,BIA,2026-08-19T14:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-09,,Checkout,MISSION,HIGH,QUESTIONNAIRE,statement,BIA,2026-08-19T14:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-10,,Checkout,MISSION,HIGH,BUSINESS_IMPACT_ANALYSIS,statement,BIA,2026-08-19," + SHA_A + "\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-11,,Checkout,MISSION,HIGH,BUSINESS_IMPACT_ANALYSIS,statement,BIA,2026-08-19T14:00:00Z,ABC\r\n"
                + "wazuh-primary,SOURCE_NAME_ONLY,web-12,,Checkout,MISSION,HIGH,BUSINESS_IMPACT_ANALYSIS,,BIA,2026-08-19T14:00:00Z," + SHA_A + "\r\n";
        BusinessImpactCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 0;
        assert report.quarantinedRows() == 8;
        assert report.issueSamples().stream().filter(issue -> issue.code().equals("INVALID_ASSET_IDENTITY")).count() == 2;
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_IMPACT_DIMENSION"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_IMPACT_LEVEL"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_IMPACT_METHOD"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_IMPACT_OBSERVED_AT"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_IMPACT_SOURCE_SHA256"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("MISSING_REQUIRED_VALUE"));
    }

    private static void rejectsMissingContractHeader() throws Exception {
        String csv = "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Business_Service,Impact_Dimension,Impact_Level,Impact_Method,Impact_Statement,Impact_Source,Impact_Observed_At\r\n";
        boolean rejected = false;
        try {
            analyze(csv, new ArrayList<>());
        } catch (CsvContractException expected) {
            rejected = expected.getMessage().contains("Impact_Source_SHA256");
        }
        assert rejected;
    }

    private static void keepsImpactEvidenceIndependentFromDecisionWeights() throws Exception {
        List<BusinessImpactCsvEvidence> evidence = new ArrayList<>();
        analyze(headers()
                + "wazuh-primary,SOURCE_NAME_ONLY,web-13,,Checkout,MISSION,SEVERE,BUSINESS_IMPACT_ANALYSIS,Loss of checkout blocks a core business mission,BIA-2026,2026-08-19T15:00:00Z," + SHA_A + "\r\n",
                evidence);
        assert evidence.get(0).impactLevel() == BusinessImpactCsvEvidence.ImpactLevel.SEVERE;
        String source = Files.readString(Path.of("src/main/java/io/rbvm/csv/BusinessImpactCsvEvidence.java"));
        assert !source.contains("riskScore");
        assert !source.contains("priorityTier");
        assert !source.contains("slaDays");
        assert !source.contains("impactWeight");
        assert !source.contains("lossAmount");
        assert !source.contains("cvssBaseScore");
        assert !source.contains("epssProbability");
        assert !source.contains("knownExploited");
        assert !source.contains("internetExposed");
    }

    private static BusinessImpactCsvAnalysisReport analyze(
            String csv,
            List<BusinessImpactCsvEvidence> evidence
    ) throws Exception {
        Path file = Files.createTempFile("business-impact-csv-", ".csv");
        try {
            Files.writeString(file, csv, StandardCharsets.UTF_8);
            return new BusinessImpactCsvAnalyzer().analyze(file, 10, evidence::add);
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static String headers() {
        return "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Business_Service,Impact_Dimension,Impact_Level,Impact_Method,Impact_Statement,Impact_Source,Impact_Observed_At,Impact_Source_SHA256\r\n";
    }
}
