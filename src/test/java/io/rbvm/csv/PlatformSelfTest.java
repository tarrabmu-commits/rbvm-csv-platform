package io.rbvm.csv;

import io.rbvm.asset.ManagedAssetSelfTest;
import io.rbvm.asset.ScannerManagedAssetLinkSelfTest;
import io.rbvm.context.FindingContextAssociationSelfTest;
import io.rbvm.decision.DecisionInputEvidenceSelectionSelfTest;
import io.rbvm.decision.DerivedRiskMethodologiesSelfTest;
import io.rbvm.decision.RbvmDecisionInputSnapshotSelfTest;
import io.rbvm.decision.RbvmDecisionInputSnapshotV2SelfTest;
import io.rbvm.decision.RbvmDecisionInputSnapshotV3SelfTest;
import io.rbvm.decision.RbvmDecisionMethodologyPolicySelfTest;
import io.rbvm.decision.RbvmDerivedRiskCanonicalResultSelfTest;
import io.rbvm.decision.RbvmFormulaV1ExplanationSelfTest;
import io.rbvm.decision.RbvmFormulaV1SelfTest;
import io.rbvm.decision.RbvmResolvedDecisionInputSelfTest;
import io.rbvm.decision.RbvmRiskMethodSelectionPolicySelfTest;
import io.rbvm.postgres.DecisionInputSnapshotMaterializerSelfTest;
import io.rbvm.postgres.DecisionRuntimeFactorySelfTest;
import io.rbvm.postgres.DefaultDerivedRiskResultMaterializerSelfTest;
import io.rbvm.postgres.DefaultFormulaResultMaterializerSelfTest;
import io.rbvm.postgres.DerivedRiskResultReplayVerifierSelfTest;
import io.rbvm.postgres.FormulaResultReplayVerifierSelfTest;
import io.rbvm.postgres.PostgresDecisionInputEvidenceResolverSelfTest;
import io.rbvm.postgres.PostgresDecisionInputSnapshotBuilderSelfTest;
import io.rbvm.postgres.PostgresDecisionInputSnapshotStoreSelfTest;
import io.rbvm.postgres.PostgresDecisionMethodologyPolicyStoreSelfTest;
import io.rbvm.postgres.PostgresFoundationSelfTest;
import io.rbvm.postgres.PostgresManagedAssetRegistrySelfTest;
import io.rbvm.postgres.PostgresScannerManagedAssetLinkRegistrySelfTest;

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
        AssetClassificationGuideV1SelfTest.main(args);
        ManagedAssetSelfTest.main(args);
        ScannerManagedAssetLinkSelfTest.main(args);
        FindingContextAssociationSelfTest.main(args);
        ManagedAssetApiSelfTest.main(args);
        ScannerManagedAssetLinkApiSelfTest.main(args);
        FindingContextAssociationApiSelfTest.main(args);
        CvssV31BaseScoreCalculatorSelfTest.main(args);
        CvssV31CsvContractSelfTest.main(args);
        CisaKevEvidenceSelfTest.main(args);
        CisaKevCsvContractSelfTest.main(args);
        EpssCsvContractSelfTest.main(args);
        RbvmDecisionMethodologyPolicySelfTest.main(args);
        RbvmDecisionInputSnapshotSelfTest.main(args);
        RbvmDecisionInputSnapshotV2SelfTest.main(args);
        RbvmDecisionInputSnapshotV3SelfTest.main(args);
        DecisionInputEvidenceSelectionSelfTest.main(args);
        RbvmResolvedDecisionInputSelfTest.main(args);
        RbvmFormulaV1SelfTest.main(args);
        RbvmFormulaV1ExplanationSelfTest.main(args);
        DerivedRiskMethodologiesSelfTest.main(args);
        RbvmDerivedRiskCanonicalResultSelfTest.main(args);
        RbvmRiskMethodSelectionPolicySelfTest.main(args);
        FormulaResultReplayVerifierSelfTest.main(args);
        DefaultFormulaResultMaterializerSelfTest.main(args);
        DerivedRiskResultReplayVerifierSelfTest.main(args);
        DefaultDerivedRiskResultMaterializerSelfTest.main(args);
        FormulaCatalogApiSelfTest.main(args);
        FormulaResultApiSelfTest.main(args);
        DerivedRiskResultApiSelfTest.main(args);
        RiskMethodSelectionPolicyApiSelfTest.main(args);
        DecisionInputApiSelfTest.main(args);
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
        CsvManagedAssetHttpSelfTest.main(args);
        CsvScannerManagedAssetLinkHttpSelfTest.main(args);
        CsvFindingContextAssociationHttpSelfTest.main(args);
        CsvFormulaCatalogHttpSelfTest.main(args);
        CsvFormulaResultHttpSelfTest.main(args);
        CsvFormulaResultMaterializationHttpSelfTest.main(args);
        CsvDerivedRiskResultHttpSelfTest.main(args);
        CsvRiskMethodSelectionPolicyHttpSelfTest.main(args);
        CsvDecisionInputHttpSelfTest.main(args);
        CanonicalProjectionSelfTest.main(args);
        PostgresFoundationSelfTest.main(args);
        PostgresManagedAssetRegistrySelfTest.main(args);
        PostgresScannerManagedAssetLinkRegistrySelfTest.main(args);
        PostgresDecisionMethodologyPolicyStoreSelfTest.main(args);
        PostgresDecisionInputSnapshotStoreSelfTest.main(args);
        PostgresDecisionInputSnapshotBuilderSelfTest.main(args);
        DecisionInputSnapshotMaterializerSelfTest.main(args);
        DecisionRuntimeFactorySelfTest.main(args);
        PostgresDecisionInputEvidenceResolverSelfTest.main(args);
        System.out.println("PlatformSelfTest: PASS");
    }
}
