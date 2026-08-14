package io.rbvm.csv;

import io.rbvm.postgres.PostgresFoundationSelfTest;

import io.rbvm.domain.DomainCatalogSelfTest;
import io.rbvm.security.ApiSecuritySelfTest;

public final class PlatformSelfTest {
    private PlatformSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        CsvContractSelfTest.main(args);
        DomainCatalogSelfTest.main(args);
        ApiSecuritySelfTest.main(args);
        CsvHttpSelfTest.main(args);
        CanonicalProjectionSelfTest.main(args);
        PostgresFoundationSelfTest.main(args);
        System.out.println("PlatformSelfTest: PASS");
    }
}
