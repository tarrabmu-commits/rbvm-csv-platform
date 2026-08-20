package io.rbvm.csv;

import io.rbvm.decision.DecisionInputEvidenceSelectionSelfTest;
import io.rbvm.decision.RbvmDecisionInputSnapshotSelfTest;
import io.rbvm.decision.RbvmDecisionMethodologyPolicySelfTest;
import io.rbvm.decision.RbvmResolvedDecisionInputSelfTest;
import io.rbvm.postgres.DecisionInputSnapshotMaterializerSelfTest;
import io.rbvm.postgres.DecisionRuntimeFactorySelfTest;
import io.rbvm.postgres.PostgresDecisionInputSnapshotBuilderSelfTest;
import io.rbvm.postgres.PostgresDecisionInputSnapshotStoreSelfTest;
import io.rbvm.postgres.PostgresDecisionMethodologyPolicyStoreSelfTest;
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
        AssetContextCsvContractSelfTest.main(args);
        CvssV31BaseScoreCalculatorSelfTest.main(args);
        CvssV31CsvContractSelfTest.main(args);
        CisaKevEvidenceSelfTest.main(args);
        CisaKevCsvContractSelfTest.main(args);
        EpssCsvContractSelfTest.main(args);
        RbvmDecisionMethodologyPolicySelfTest.main(args);
        RbvmDecisionInputSnapshotSelfTest.main(args);
        DecisionInputEvidenceSelectionSelfTest.main(args);
        RbvmResolvedDecisionInputSelfTest.main(args);
        DomainCatalogSelfTest.main(args);
        ApiSecuritySelfTest.main(args);
        CsvHttpSelfTest.main(args);
        CsvApplicabilityHttpSelfTest.main(args);
        CsvCvssV31HttpSelfTest.main(args);
        CsvCisaKevHttpSelfTest.main(args);
        CsvEpssHttpSelfTest.main(args);
        CsvAssetContextHttpSelfTest.main(args);
        CsvNetworkReachabilityHttpSelfTest.main(args);
        CsvBusinessImpactHttpSelfTest.main(args);
        CanonicalProjectionSelfTest.main(args);
        PostgresFoundationSelfTest.main(args);
        PostgresDecisionMethodologyPolicyStoreSelfTest.main(args);
        PostgresDecisionInputSnapshotStoreSelfTest.main(args);
        PostgresDecisionInputSnapshotBuilderSelfTest.main(args);
        DecisionInputSnapshotMaterializerSelfTest.main(args);
        DecisionRuntimeFactorySelfTest.main(args);
        System.out.println("PlatformSelfTest: PASS");
    }
}
