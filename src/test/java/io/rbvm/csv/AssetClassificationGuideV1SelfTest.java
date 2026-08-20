package io.rbvm.csv;

import io.rbvm.csv.AssetClassificationGuideV1.Field;
import io.rbvm.csv.AssetClassificationGuideV1.Guide;
import io.rbvm.csv.AssetClassificationGuideV1.RequirementOrigin;
import io.rbvm.csv.AssetContextCsvEvidence.BusinessCriticality;
import io.rbvm.csv.AssetContextCsvEvidence.Environment;

import java.util.Arrays;
import java.util.List;

public final class AssetClassificationGuideV1SelfTest {
    private AssetClassificationGuideV1SelfTest() {
    }

    public static void main(String[] args) {
        exposesVersionedGuideWithoutInventingTaxonomy();
        separatesStandardsMappingsFromRbvmPolicy();
        preservesUnknownAndEvidenceBoundaries();
        System.out.println("AssetClassificationGuideV1SelfTest: PASS");
    }

    private static void exposesVersionedGuideWithoutInventingTaxonomy() {
        Guide guide = AssetClassificationGuideV1.guide();
        assert guide.contractId().equals("ASSET_CLASSIFICATION_GUIDE_V1");
        assert guide.revision() == 1;
        assert guide.semantics().equals("CUSTOMER_CONFIRMED_ASSET_CONTEXT_SELECTION_GUIDE");
        assert guide.standardsBaseline().equals("RBVM_STANDARDS_BASELINE_V1");
        assert guide.fields().size() == 4;

        assert optionValues(guide.field("Environment")).equals(enumNames(Environment.values()));
        assert optionValues(guide.field("Business_Criticality"))
                .equals(enumNames(BusinessCriticality.values()));

        assert guide.field("Business_Service").options().isEmpty();
        assert guide.field("Business_Owner").options().isEmpty();
        assert guide.references().stream().allMatch(reference ->
                "https".equalsIgnoreCase(reference.uri().getScheme()));
    }

    private static void separatesStandardsMappingsFromRbvmPolicy() {
        Guide guide = AssetClassificationGuideV1.guide();
        assert guide.field("Environment").origin() == RequirementOrigin.RBVM_POLICY;
        assert guide.field("Business_Service").origin() == RequirementOrigin.STANDARD_DERIVED;
        assert guide.field("Business_Owner").origin() == RequirementOrigin.STANDARD_DERIVED;
        assert guide.field("Business_Criticality").origin() == RequirementOrigin.STANDARD_DERIVED;

        List<String> referenceIds = guide.references().stream()
                .map(AssetClassificationGuideV1.Reference::id)
                .toList();
        assert referenceIds.equals(List.of("NIST_CSF_2_0", "NIST_IR_8286D_UPD1", "FIPS_199"));
    }

    private static void preservesUnknownAndEvidenceBoundaries() {
        Guide guide = AssetClassificationGuideV1.guide();
        assert optionValues(guide.field("Environment")).contains("UNKNOWN");
        assert optionValues(guide.field("Business_Criticality")).contains("UNKNOWN");

        String criticalityGuidance = String.join(" ", guide.field("Business_Criticality").prompts());
        assert criticalityGuidance.contains("Never derive Business Criticality from CVSS, KEV, EPSS");

        String missionCritical = guide.field("Business_Criticality").options().stream()
                .filter(option -> option.value().equals("MISSION_CRITICAL"))
                .findFirst()
                .orElseThrow()
                .guidance();
        assert missionCritical.contains("mission or business function");
        assert !missionCritical.contains("CVSS");
        assert !missionCritical.contains("EPSS");
    }

    private static List<String> optionValues(Field field) {
        return field.options().stream().map(AssetClassificationGuideV1.Option::value).toList();
    }

    private static List<String> enumNames(Enum<?>[] values) {
        return Arrays.stream(values).map(Enum::name).toList();
    }
}
