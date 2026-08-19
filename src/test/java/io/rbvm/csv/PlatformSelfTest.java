package io.rbvm.csv;

import io.rbvm.postgres.PostgresFoundationSelfTest;

import io.rbvm.domain.DomainCatalogSelfTest;
import io.rbvm.security.ApiSecuritySelfTest;

public final class PlatformSelfTest {
    private PlatformSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        CsvContractSelfTest.main(args);
        CanonicalFindingIdentitySelfTest.main(args);
        CanonicalFindingStateSelfTest.main(args);
        ApplicabilityEvidenceSelfTest.main(args);
        ApplicabilityCsvContractSelfTest.main(args);
        CvssV31BaseScoreCalculatorSelfTest.main(args);
        CvssV31CsvContractSelfTest.main(args);
        CisaKevEvidenceSelfTest.main(args);
        DomainCatalogSelfTest.main(args);
        ApiSecuritySelfTest.main(args);
        CsvHttpSelfTest.main(args);
        CsvApplicabilityHttpSelfTest.main(args);
        CsvCvssV31HttpSelfTest.main(args);
        CanonicalProjectionSelfTest.main(args);
        PostgresFoundationSelfTest.main(args);
        System.out.println("PlatformSelfTest: PASS");
    }
}
