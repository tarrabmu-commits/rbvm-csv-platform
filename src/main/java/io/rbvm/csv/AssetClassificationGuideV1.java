package io.rbvm.csv;

import io.rbvm.csv.AssetContextCsvEvidence.BusinessCriticality;
import io.rbvm.csv.AssetContextCsvEvidence.Environment;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Versioned, methodology-neutral customer guidance for selecting Asset Context values.
 *
 * <p>The guide explains canonical choices and their standards basis. It deliberately does not
 * calculate risk, priority, SLA, or an automatic Business Criticality recommendation.</p>
 */
public final class AssetClassificationGuideV1 {
    public static final String CONTRACT_ID = "ASSET_CLASSIFICATION_GUIDE_V1";
    public static final int REVISION = 1;
    public static final String SEMANTICS = "CUSTOMER_CONFIRMED_ASSET_CONTEXT_SELECTION_GUIDE";
    public static final String STANDARDS_BASELINE = "RBVM_STANDARDS_BASELINE_V1";

    private static final List<Reference> REFERENCES = List.of(
            new Reference(
                    "NIST_CSF_2_0",
                    "NIST Cybersecurity Framework 2.0",
                    URI.create("https://www.nist.gov/cyberframework")
            ),
            new Reference(
                    "NIST_IR_8286D_UPD1",
                    "NIST IR 8286D Update 1 (2025)",
                    URI.create("https://csrc.nist.gov/pubs/ir/8286/d/upd1/final")
            ),
            new Reference(
                    "FIPS_199",
                    "FIPS PUB 199",
                    URI.create("https://csrc.nist.gov/pubs/fips/199/final")
            )
    );

    private static final Guide GUIDE = new Guide(
            CONTRACT_ID,
            REVISION,
            SEMANTICS,
            STANDARDS_BASELINE,
            List.of(
                    environmentField(),
                    businessServiceField(),
                    businessOwnerField(),
                    businessCriticalityField()
            ),
            REFERENCES
    );

    private AssetClassificationGuideV1() {
    }

    public static Guide guide() {
        return GUIDE;
    }

    private static Field environmentField() {
        return new Field(
                "Environment",
                RequirementOrigin.RBVM_POLICY,
                "How the organization actually uses this asset in its delivery lifecycle.",
                List.of(
                        option(Environment.PRODUCTION,
                                "Actively delivers a live business, customer, employee, mission, or operational service."),
                        option(Environment.PRE_PRODUCTION,
                                "Validates staging, acceptance, or release-candidate changes before production; it is not the live production service."),
                        option(Environment.DEVELOPMENT,
                                "Primarily supports software or configuration development activity."),
                        option(Environment.TEST,
                                "Primarily supports QA, integration, automated, or other controlled testing."),
                        option(Environment.SANDBOX,
                                "Supports isolated experimentation, prototypes, demonstrations, or disposable exploration."),
                        option(Environment.DISASTER_RECOVERY,
                                "Primarily provides continuity or recovery capability for another service or environment."),
                        option(Environment.UNKNOWN,
                                "The environment was assessed but cannot be determined from reliable organizational information.")
                ),
                List.of(
                        "Do not infer Environment from the asset name.",
                        "Choose based on current organizational use, not vulnerability severity."
                ),
                List.of("NIST_CSF_2_0", "NIST_IR_8286D_UPD1")
        );
    }

    private static Field businessServiceField() {
        return new Field(
                "Business_Service",
                RequirementOrigin.STANDARD_DERIVED,
                "The customer-defined business/application service or capability supported by the asset.",
                List.of(),
                List.of(
                        "What business, mission, customer, employee, or operational capability stops or degrades if this asset is unavailable or untrusted?",
                        "Which service owner would recognize this asset as part of their service?",
                        "Use a business/application capability label; do not silently substitute a product or technology name.",
                        "Use UNKNOWN when the field was assessed but the service cannot currently be identified."
                ),
                List.of("NIST_CSF_2_0", "NIST_IR_8286D_UPD1")
        );
    }

    private static Field businessOwnerField() {
        return new Field(
                "Business_Owner",
                RequirementOrigin.STANDARD_DERIVED,
                "The customer-supplied accountable person or team for the business/application context represented by the asset.",
                List.of(),
                List.of(
                        "Who is accountable for the business/application service supported by this asset?",
                        "Who can make or approve business decisions about disruption, risk acceptance, or service priority?",
                        "Do not assume the business owner is the system administrator or infrastructure operator.",
                        "Use UNKNOWN when ownership was assessed but cannot currently be established."
                ),
                List.of("NIST_CSF_2_0")
        );
    }

    private static Field businessCriticalityField() {
        return new Field(
                "Business_Criticality",
                RequirementOrigin.STANDARD_DERIVED,
                "The organization's qualitative importance classification for the asset; it is not vulnerability severity.",
                List.of(
                        option(BusinessCriticality.MISSION_CRITICAL,
                                "Reliable organizational/BIA evidence shows the asset directly enables an essential mission or business function whose loss would cripple or prevent that function without an acceptable substitute."),
                        option(BusinessCriticality.HIGH,
                                "Loss or compromise would cause a serious adverse effect on an important business or mission service, without meeting the stronger MISSION_CRITICAL condition."),
                        option(BusinessCriticality.MODERATE,
                                "Loss or compromise would cause a meaningful adverse effect requiring response, while core functions can continue with tolerable degradation or workable alternatives."),
                        option(BusinessCriticality.LOW,
                                "Loss or compromise is expected to have limited adverse organizational effect and does not materially prevent important business or mission functions from continuing."),
                        option(BusinessCriticality.UNKNOWN,
                                "Criticality was considered, but reliable business-impact or ownership information is insufficient for a defensible classification.")
                ),
                List.of(
                        "Which mission or business function does the asset enable?",
                        "What is the effect of loss of availability, integrity, or confidentiality?",
                        "Is there an effective alternative or workaround?",
                        "Do other important services depend on this asset?",
                        "Could failure cause serious operational, financial, regulatory, safety, reputational, or mission consequences?",
                        "Never derive Business Criticality from CVSS, KEV, EPSS, Wazuh severity, or finding count."
                ),
                List.of("NIST_IR_8286D_UPD1", "FIPS_199")
        );
    }

    private static Option option(Enum<?> value, String guidance) {
        return new Option(value.name(), guidance);
    }

    public enum RequirementOrigin {
        STANDARD,
        STANDARD_DERIVED,
        RBVM_POLICY
    }

    public record Guide(
            String contractId,
            int revision,
            String semantics,
            String standardsBaseline,
            List<Field> fields,
            List<Reference> references
    ) {
        public Guide {
            contractId = requireText(contractId, "contractId");
            if (revision < 1) {
                throw new IllegalArgumentException("revision must be positive");
            }
            semantics = requireText(semantics, "semantics");
            standardsBaseline = requireText(standardsBaseline, "standardsBaseline");
            fields = List.copyOf(fields);
            references = List.copyOf(references);
            if (fields.isEmpty() || references.isEmpty()) {
                throw new IllegalArgumentException("guide requires fields and references");
            }
            Map<String, Reference> byId = references.stream().collect(Collectors.toUnmodifiableMap(
                    Reference::id,
                    Function.identity()
            ));
            for (Field field : fields) {
                for (String referenceId : field.referenceIds()) {
                    if (!byId.containsKey(referenceId)) {
                        throw new IllegalArgumentException("unknown guide reference: " + referenceId);
                    }
                }
            }
        }

        public Field field(String key) {
            String required = requireText(key, "key");
            return fields.stream()
                    .filter(field -> field.key().equals(required))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("unknown guide field: " + required));
        }
    }

    public record Field(
            String key,
            RequirementOrigin origin,
            String purpose,
            List<Option> options,
            List<String> prompts,
            List<String> referenceIds
    ) {
        public Field {
            key = requireText(key, "key");
            origin = Objects.requireNonNull(origin, "origin");
            purpose = requireText(purpose, "purpose");
            options = List.copyOf(options);
            prompts = copyTextList(prompts, "prompts");
            referenceIds = copyTextList(referenceIds, "referenceIds");
            if (prompts.isEmpty()) {
                throw new IllegalArgumentException("field prompts must not be empty");
            }
        }
    }

    public record Option(String value, String guidance) {
        public Option {
            value = requireText(value, "value");
            guidance = requireText(guidance, "guidance");
        }
    }

    public record Reference(String id, String title, URI uri) {
        public Reference {
            id = requireText(id, "id");
            title = requireText(title, "title");
            uri = Objects.requireNonNull(uri, "uri");
            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                throw new IllegalArgumentException("reference URI must use HTTPS");
            }
        }
    }

    private static List<String> copyTextList(List<String> values, String field) {
        Objects.requireNonNull(values, field);
        return values.stream().map(value -> requireText(value, field)).toList();
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }
}
