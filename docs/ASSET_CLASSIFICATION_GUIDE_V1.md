# Asset Classification Guide V1

`ASSET_CLASSIFICATION_GUIDE_V1` is the customer-facing selection guide for the organizational fields already defined by `ASSET_CONTEXT_CSV_V1`.

It exists to make customer classification repeatable and explainable without turning the guide into an RBVM formula.

## Contract

- Contract ID: `ASSET_CLASSIFICATION_GUIDE_V1`
- Revision: `1`
- Semantics: `CUSTOMER_CONFIRMED_ASSET_CONTEXT_SELECTION_GUIDE`
- Standards baseline: `RBVM_STANDARDS_BASELINE_V1`
- Output: guidance only; no persisted value is created by consulting the guide.
- Final authority: the customer/operator confirms the Asset Context value.
- Missing/uncertain information: use `UNKNOWN` where the canonical field supports it instead of guessing.

The guide covers:

```text
Environment
Business_Service
Business_Owner
Business_Criticality
```

It does not calculate risk, priority, treatment, remediation SLA, vulnerability applicability, network exposure, or Business/Mission Impact.

## General instruction shown to customers

Classify the asset from the perspective of how your organization actually uses it. Do not choose values based on the severity or number of vulnerabilities currently detected on the asset.

External vulnerability intelligence is evaluated independently:

```text
Wazuh finding evidence
CVSS technical severity
CISA KEV known-exploitation evidence
FIRST EPSS exploitation-probability evidence
```

None of those sources is authoritative for the customer's organizational asset classification.

## Environment guide

Origin: `RBVM_POLICY`.

### `PRODUCTION`

Use when the asset actively delivers a live business, customer, employee, mission, or operational service.

Check:

- Is real organizational work or a live service currently dependent on this asset?
- Would changing or stopping it affect live users or operations?

Do not choose merely because the hostname contains `prod`.

### `PRE_PRODUCTION`

Use for staging, acceptance, release-candidate, or other environments intended to validate changes before production and that are not themselves the live production service.

Check:

- Is the purpose to validate software/configuration before production?
- Is live production traffic or the live business process normally served elsewhere?

### `DEVELOPMENT`

Use when the primary purpose is software/configuration development by engineering teams.

Check:

- Is the asset primarily used to build or change software/configuration?
- Is it outside the formal production delivery path except for development activity?

### `TEST`

Use when the primary purpose is verification, QA, automated testing, integration testing, or similar controlled testing.

Check whether the asset exists to validate behavior rather than deliver a live service.

### `SANDBOX`

Use for isolated experimentation, prototypes, demonstrations, or disposable exploration that is not a controlled production, pre-production, development, or formal test environment.

### `DISASTER_RECOVERY`

Use when the asset's primary purpose is continuity/recovery capability for another service or environment.

Check whether the asset is maintained to restore or continue service after a disruption rather than serving as the normal live environment.

### `UNKNOWN`

Use when the environment was considered but cannot be determined from reliable organizational information.

Do not infer the answer from the asset name.

## Business Service guide

Origin: `STANDARD_DERIVED` from NIST CSF 2.0 asset/mission context and NIST IR 8286D Update 1 BIA concepts.

`Business_Service` is a customer-defined business/application service or capability supported by the asset.

Ask:

1. What business, mission, customer, employee, or operational capability stops or degrades if this asset is unavailable or untrusted?
2. Which service owner would recognize this asset as part of their service?
3. Is the proposed label a business/application capability rather than merely a technology/product name?

Examples:

```text
Technology/product        Business Service
Oracle                    Payroll
nginx                     Customer Portal
Microsoft SQL Server      Billing
Linux                     UNKNOWN unless a service is actually identified
```

Examples are not inference rules. The platform never converts a product name to a service automatically.

Use the literal `UNKNOWN` when the field was assessed but the service cannot currently be identified.

## Business Owner guide

Origin: `STANDARD_DERIVED` from NIST CSF 2.0 governance, roles, responsibilities, and authorities concepts.

`Business_Owner` is the customer-supplied accountable person or team label for the business/application context represented by the asset.

Ask:

1. Who is accountable for the business/application service supported by this asset?
2. Who can make or approve business decisions about disruption, risk acceptance, or service priority?
3. Are you entering a business/application owner rather than only the administrator who patches the operating system?

Example:

```text
Technical administration: Infrastructure Team
Business/Application owner: Finance Applications
```

The platform does not infer ownership from cloud account names, hostnames, scanner source, or package names.

Use the literal `UNKNOWN` when ownership was assessed but cannot currently be established.

## Business Criticality guide

Origin: `STANDARD_DERIVED` from NIST IR 8286D Update 1 BIA concepts and FIPS 199 potential-impact concepts.

This field describes the organization's importance of the asset. It is not vulnerability severity.

Evaluate at least these questions before confirming a value:

1. Which mission/business function or service does the asset enable?
2. What happens if the asset or service becomes unavailable?
3. What happens if information or processing on the asset loses integrity?
4. What happens if sensitive information handled by the asset loses confidentiality?
5. Is there an effective alternative or workaround?
6. Does another critical service depend on this asset?
7. Could failure cause serious operational, financial, regulatory, safety, reputational, or mission consequences?

### `MISSION_CRITICAL`

Use when reliable organizational/BIA evidence shows the asset directly enables a mission- or business-critical function and loss of the asset would cripple or prevent that essential function, with no acceptable substitute for the relevant business need.

Important standards note: `MISSION_CRITICAL` is an RBVM/customer organizational label informed by NIST BIA concepts. It is not a literal FIPS 199 category.

Do not choose because:

- the asset has a Critical CVSS finding;
- the asset has a KEV-listed vulnerability;
- EPSS is high;
- the asset has many findings.

### `HIGH`

Use when loss or compromise of the asset would cause a serious adverse effect on an important business/mission service or organizational operation, but the available evidence does not support the stronger `MISSION_CRITICAL` condition.

Examples of evidence may include severe operational degradation, major financial/regulatory impact, or a highly constrained workaround. The organization remains responsible for defining what constitutes a serious adverse effect in its context.

### `MODERATE`

Use when loss or compromise would cause a meaningful adverse effect requiring management attention or operational response, while core organizational functions can continue with tolerable degradation or workable alternatives.

### `LOW`

Use when loss or compromise is expected to have limited adverse organizational effect and does not materially prevent important business/mission functions from continuing.

`LOW` does not mean that vulnerabilities on the asset are safe, non-exploitable, or ignorable.

### `UNKNOWN`

Use when the customer has considered criticality but lacks enough reliable business-impact or ownership information to make a defensible classification.

`UNKNOWN` is preferred over a guessed `LOW`, `MODERATE`, `HIGH`, or `MISSION_CRITICAL` value.

## Interactive behavior

The V1 web guide may use navigation, expandable choices, checklists, examples, and links to the authoritative references above.

The following are forbidden in V1:

- hidden numeric scoring behind the guide;
- summing answers to manufacture Business Criticality;
- auto-selecting a value from hostname, OS, product, CVE, CVSS, KEV, EPSS, or finding count;
- auto-saving a suggested value;
- describing `MISSION_CRITICAL` as a FIPS 199 category;
- describing the exact Environment vocabulary as a NIST taxonomy.

A later guide revision may add a recommendation decision table only if its rules are explicitly approved, versioned, tested, and distinguished from external standards.

## Reference display

The customer-facing guide should surface the relevant basis without requiring the user to read standards documents before proceeding:

- **NIST CSF 2.0** — asset prioritization and organizational context.
- **NIST IR 8286D Update 1 (2025)** — BIA-informed asset criticality, mission/business objectives, and dependencies.
- **FIPS 199** — LOW/MODERATE/HIGH potential-impact concepts for confidentiality, integrity, and availability.

The interface must use wording such as `Based on` or `Informed by` for platform mappings. It must not imply that NIST assigned the customer's final classification.

## Future write-path provenance

The current Asset Context runtime accepts `ASSET_CONTEXT_CSV_V1`; it does not yet expose a single-asset customer form write API.

When a direct customer UI write path is introduced, the design should preserve at minimum:

```text
customer-confirmed Asset Context values
context source = CUSTOMER_UI (or an equally explicit semantic source)
server-observed timestamp
immutable evidence provenance
guide revision used, when the classification was made through this guide
```

Adding guide provenance to persistence must be an explicit schema/contract evolution; V1 does not silently overload existing CSV fields.