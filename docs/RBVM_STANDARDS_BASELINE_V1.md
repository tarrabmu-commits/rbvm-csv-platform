# RBVM Standards Baseline V1

`RBVM_STANDARDS_BASELINE_V1` records the external standards and platform-policy boundaries used by the asset-context experience before any RBVM formula exists.

This baseline is a traceability document, not a claim that the platform is certified by NIST, FIRST, CISA, CERT/CC, ISO, or any other body. A platform term is never labeled as a standards term unless the cited source actually defines that concept or vocabulary.

## Classification of requirements

Every rule in this baseline is labeled with one of three origins:

- `STANDARD`: a concept or vocabulary used directly from an authoritative source.
- `STANDARD_DERIVED`: a platform mapping or guidance rule derived from one or more authoritative concepts, but not a literal standards vocabulary.
- `RBVM_POLICY`: a deliberate platform rule needed for deterministic, auditable evidence handling; it must not be presented as a requirement of an external standard.

## Authoritative references

| Reference ID | Authority | Publication | Use in this baseline |
|---|---|---|---|
| `NIST_CSF_2_0` | NIST | Cybersecurity Framework 2.0 | Asset inventory and prioritization based on classification, criticality, resources, and mission impact; governance context. |
| `NIST_IR_8286D_UPD1` | NIST | IR 8286D Update 1, *Using Business Impact Analysis to Inform Risk Prioritization and Response* (2025) | Business-impact analysis, mission/business objectives, asset criticality/sensitivity, dependencies, and repeatable asset valuation. |
| `FIPS_199` | NIST | FIPS PUB 199, *Standards for Security Categorization of Federal Information and Information Systems* | `LOW`, `MODERATE`, and `HIGH` potential-impact concepts for confidentiality, integrity, and availability. |
| `FIRST_CVSS` | FIRST | Common Vulnerability Scoring System | Technical vulnerability severity; not organizational risk or asset criticality. |
| `FIRST_EPSS` | FIRST | Exploit Prediction Scoring System | Probability-oriented exploitation evidence; not asset criticality or a complete organizational risk score. |
| `CISA_KEV` | CISA | Known Exploited Vulnerabilities Catalog | Evidence that a CVE is known to have been exploited in the wild; an input to prioritization, not an asset-criticality classification. |
| `CERT_SSVC` | CERT/CC | Stakeholder-Specific Vulnerability Categorization | Decision-oriented separation of vulnerability facts from stakeholder-specific context; useful design reference, not adopted wholesale by V1. |

Primary public references:

- NIST CSF 2.0: <https://www.nist.gov/cyberframework>
- NIST IR 8286D Update 1: <https://csrc.nist.gov/pubs/ir/8286/d/upd1/final>
- FIPS 199: <https://csrc.nist.gov/pubs/fips/199/final>
- FIRST CVSS: <https://www.first.org/cvss/>
- FIRST EPSS: <https://www.first.org/epss/>
- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CERT/CC SSVC: <https://certcc.github.io/SSVC/>

## Asset Context mapping

The canonical Asset Context contract currently contains:

```text
Environment
Business_Service
Business_Owner
Business_Criticality
```

The customer is the authority for these organizational facts. Wazuh names, CVSS, KEV, EPSS, CVE descriptions, and other external vulnerability data must not silently manufacture customer context.

### Environment

Current values:

```text
PRODUCTION
PRE_PRODUCTION
DEVELOPMENT
TEST
SANDBOX
DISASTER_RECOVERY
UNKNOWN
```

Origin: `RBVM_POLICY`.

NIST provides organizational- and asset-context principles, but this exact environment vocabulary is not a NIST taxonomy. The platform therefore documents each value operationally and never labels the list as a NIST classification.

The platform must not infer an environment from an asset name such as `*-prod`, `*-uat`, or `*-dev`. Such names may help a customer investigate, but they are not authoritative context evidence.

### Business Service

Origin: `STANDARD_DERIVED`.

NIST CSF 2.0 and NIST IR 8286D Update 1 support understanding which assets enable organizational mission/business objectives and services. The platform therefore asks the customer to identify the business/application service supported by the asset.

The service label is customer-defined. Product technology is not silently converted into a business service. For example, an Oracle host may support `Payroll`; `Oracle` is not automatically the Business Service.

`UNKNOWN` means the customer assessed the field but cannot currently identify the service.

### Business Owner

Origin: `STANDARD_DERIVED`.

NIST CSF 2.0 governance concepts require roles, responsibilities, and authorities to be understood. The platform uses `Business_Owner` as the customer-supplied accountable person/team label for the business or application context represented by the asset evidence.

The Business Owner is not assumed to be the system administrator or technical infrastructure owner. The platform does not infer ownership from hostnames, cloud accounts, package names, or scanner metadata.

`UNKNOWN` means ownership was assessed but is not currently known.

### Business Criticality

Current values:

```text
MISSION_CRITICAL
HIGH
MODERATE
LOW
UNKNOWN
```

Origin: `STANDARD_DERIVED`.

`FIPS_199` directly defines `LOW`, `MODERATE`, and `HIGH` potential-impact concepts for confidentiality, integrity, and availability. `NIST_IR_8286D_UPD1` provides the broader BIA basis for identifying assets that enable mission/business objectives and determining factors that make assets critical or sensitive.

The platform's `Business_Criticality` is an organizational asset classification. It is **not** a copy of the FIPS 199 security-category calculation:

- `MISSION_CRITICAL` is an RBVM/customer organizational label informed by NIST BIA mission/business-criticality concepts. It is not a literal FIPS 199 category.
- `HIGH`, `MODERATE`, and `LOW` are interpreted using documented business-impact guidance, not vulnerability severity.
- `UNKNOWN` is an explicit assessed value when the customer cannot make a defensible classification.

The guide must never suggest that a Critical CVSS score, KEV listing, high EPSS probability, or a large finding count makes an asset `MISSION_CRITICAL` or `HIGH`.

## UNKNOWN and missing evidence

Origin: `RBVM_POLICY`.

The project invariant is:

```text
UNKNOWN > invented data
```

Two states remain distinct:

- no Asset Context observation: no usable customer context evidence was supplied;
- explicit `UNKNOWN`: the customer assessed the field and could not determine a value.

The guide must always provide an `UNKNOWN` path where the canonical contract supports it. It must not force a customer to choose a more confident classification merely to complete a form.

This differs from conservative-default patterns used by some decision systems, including some SSVC collection guidance. V1 does not adopt a rule such as "unknown exposure means open" or "unknown mission impact means worst case". Any future conservative decision policy must be explicit, versioned, and downstream of evidence capture.

## Separation from vulnerability intelligence

The following boundaries are normative platform guardrails:

| Evidence | Question answered | Must not become |
|---|---|---|
| Wazuh source severity | What severity label did the scanner observation report? | Customer Business Criticality |
| CVSS | How technically severe is the vulnerability under the applicable CVSS contract? | Organizational risk or asset value |
| CISA KEV | Was the CVE listed in a validated KEV snapshot? | Automatic customer priority or SLA |
| EPSS | What exploitation-probability evidence did FIRST publish? | Asset criticality or a complete risk score |
| Asset Context | What organizational context did the customer/source explicitly provide for the asset? | A hidden numeric multiplier |

The current canonical decision methodology already preserves these dimensions independently and preserves missing, stale, and ambiguous evidence rather than fabricating values.

## Guide governance

The customer-facing selection guide is versioned separately as `ASSET_CLASSIFICATION_GUIDE_V1`.

V1 rules:

1. The guide explains criteria; it does not calculate risk, priority, SLA, or a numeric score.
2. The guide does not auto-save a classification.
3. The customer remains the authority that confirms the value stored as Asset Context evidence.
4. Examples are illustrative, not automatic inference rules.
5. Each guide field states whether its vocabulary is `STANDARD`, `STANDARD_DERIVED`, or `RBVM_POLICY`.
6. A future change that materially changes classification guidance must create a new guide revision rather than silently rewriting the meaning of historical customer choices.

## Deliberate non-goals

This baseline does not define:

- an RBVM formula, weights, coefficients, or thresholds;
- priority tiers or remediation SLA;
- a CVSS v3.1 to v4.0 conversion;
- a Business Criticality to Business Impact numeric conversion;
- a default value for missing customer context;
- automatic inference from asset names, OS names, products, CVEs, CVSS, KEV, or EPSS;
- certification or blanket "NIST compliant" status.

Those remain separate, explicit decisions.