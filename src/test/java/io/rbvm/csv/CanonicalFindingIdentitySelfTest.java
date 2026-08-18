package io.rbvm.csv;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class CanonicalFindingIdentitySelfTest {
    private CanonicalFindingIdentitySelfTest() {
    }

    public static void main(String[] args) throws Exception {
        groupsRepeatedV1ObservationsWithoutClaimingStableIdentity();
        usesStablePackageCoordinatesForV2();
        separatesDifferentV2PackageVersions();
        System.out.println("CanonicalFindingIdentitySelfTest: PASS");
    }

    private static void groupsRepeatedV1ObservationsWithoutClaimingStableIdentity() throws Exception {
        String csv = "Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At\r\n"
                + "hodor-aio,CVE-2026-25087,High,description,pyarrow,https://example.test/1,Ubuntu,2026-06-11T17:53:10.302Z\r\n"
                + "hodor-aio,CVE-2026-25087,High,description,pyarrow,https://example.test/2,Ubuntu,2026-06-11T17:53:10.342Z\r\n";
        List<WazuhObservation> observations = analyze(csv, CsvContractV1.ID);
        assert observations.size() == 2;

        CanonicalFindingIdentity first = observations.get(0).canonicalFindingIdentity();
        CanonicalFindingIdentity second = observations.get(1).canonicalFindingIdentity();
        assert first.equals(second);
        assert first.strength() == CanonicalFindingIdentity.Strength.SOURCE_LIMITED;
        assert !first.isSourceStable();
    }

    private static void usesStablePackageCoordinatesForV2() throws Exception {
        String csv = v2Headers()
                + "renamed-agent,001,CVE-2026-4321,High,description,openssl,3.0.2,amd64,https://example.test/1,Ubuntu,ACTIVE,2026-08-01T10:00:00Z,\r\n"
                + "another-display-name,001,CVE-2026-4321,High,description,openssl,3.0.2,amd64,https://example.test/2,Ubuntu,ACTIVE,2026-08-02T10:00:00Z,\r\n";
        List<WazuhObservation> observations = analyze(csv, CsvContractV2.ID);
        assert observations.size() == 2;

        CanonicalFindingIdentity first = observations.get(0).canonicalFindingIdentity();
        CanonicalFindingIdentity second = observations.get(1).canonicalFindingIdentity();
        assert first.equals(second);
        assert first.strength() == CanonicalFindingIdentity.Strength.SOURCE_STABLE;
        assert first.isSourceStable();
    }

    private static void separatesDifferentV2PackageVersions() throws Exception {
        String csv = v2Headers()
                + "agent,001,CVE-2026-4321,High,description,openssl,3.0.2,amd64,https://example.test/1,Ubuntu,ACTIVE,2026-08-01T10:00:00Z,\r\n"
                + "agent,001,CVE-2026-4321,High,description,openssl,3.0.3,amd64,https://example.test/2,Ubuntu,ACTIVE,2026-08-02T10:00:00Z,\r\n";
        List<WazuhObservation> observations = analyze(csv, CsvContractV2.ID);
        assert observations.size() == 2;
        assert !observations.get(0).canonicalFindingIdentity()
                .equals(observations.get(1).canonicalFindingIdentity());
    }

    private static List<WazuhObservation> analyze(String csv, String contractId) throws Exception {
        Path file = Files.createTempFile("canonical-finding-", ".csv");
        try {
            Files.writeString(file, csv, StandardCharsets.UTF_8);
            List<WazuhObservation> observations = new ArrayList<>();
            new WazuhCsvAnalyzer("canonical-test", contractId).analyze(file, 0, observations::add);
            return observations;
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static String v2Headers() {
        return "Agent,Agent_ID,CVE_ID,Severity,CVE_Description,Affected_Product,"
                + "Package_Version,Package_Architecture,References,OS_name,Finding_Status,"
                + "Detected_At,Resolved_At\r\n";
    }
}
