# Global RBVM Formula Atlas V1

Contract ID: `GLOBAL_RBVM_FORMULA_ATLAS_V1`

Reviewed: 2026-08-22

This document is a research baseline for the future RBVM Formula Contract. It is **not** a scoring specification and does not authorize any runtime risk, priority, SLA, or remediation calculation.

The purpose is to separate fundamentally different model classes before RBVM chooses its own methodology:

- technical severity,
- exploit probability,
- known exploitation,
- qualitative risk assessment,
- decision-tree prioritization,
- quantitative loss analysis,
- weakness scoring,
- proprietary vendor risk/prioritization scores.

The platform must not copy a public or proprietary score merely because it is called “risk.” Every model below has a different unit of analysis, data assumptions, output semantics, and treatment of missing context.

## 1. Reference taxonomy

| Model / source | Primary role | Typical output | RBVM interpretation |
|---|---|---|---|
| NIST SP 800-30 Rev. 1 | Risk assessment guidance | likelihood + impact based risk level | Governance framing; not a vulnerability scoring formula |
| NIST IR 8286D Update 1 | Business impact / asset criticality | BIA-derived impact values and asset categorization | Basis for customer-owned context and business impact |
| FIRST CVSS | Technical vulnerability severity | 0–10 severity score + vector | Technical severity evidence only |
| FIRST EPSS | Exploit probability | 0–1 probability + percentile | Probability evidence; not complete risk |
| CISA KEV | Confirmed exploitation | membership / exploitation evidence | Known exploitation evidence; prioritization input only |
| CERT/SEI SSVC 2.0 | Vulnerability response prioritization | decision-tree outcome | Strong reference for explicit, explainable policy decisions |
| OWASP Risk Rating Methodology | AppSec risk estimation | likelihood/impact categories | Historical/customizable pattern; numeric factors are not authoritative for RBVM |
| MITRE CWSS 1.0 | Software weakness scoring | 0–100 weakness score | Historical structural reference for base × attack-surface × environment modeling |
| Open FAIR | Quantitative information-risk analysis | frequency/magnitude distributions / economic loss | Strong quantitative-risk reference, but requires data not currently present in RBVM Decision Input |
| Tenable VPR / Unified Risk Scoring | Vendor vulnerability prioritization | proprietary priority/risk score | Benchmark only; do not copy hidden/proprietary model |
| Qualys TruRisk | Vendor asset/vulnerability risk | 0–1000 score | Benchmark for asset criticality + threat/severity aggregation; vendor-specific weights/formulas |
| Rapid7 Active Risk | Vendor vulnerability risk | 0–1000 score | Benchmark for CVSS + exploit/threat intelligence; exact model is proprietary |

## 2. Standards and open methodologies

### 2.1 NIST SP 800-30 Rev. 1

Official source: https://csrc.nist.gov/pubs/sp/800/30/r1/final

NIST frames risk assessment around threat sources/events, vulnerabilities and predisposing conditions, likelihood, impact, and resulting risk. It describes risk as a combination of likelihood and impact, but does not prescribe a universal vulnerability formula for RBVM products.

**Useful for RBVM**

- Preserve the conceptual split between likelihood and impact.
- Treat environment/predisposing conditions as real inputs, not decorative metadata.
- Keep uncertainty explicit.
- Keep risk assessment separate from risk response/treatment.

**Do not infer**

- NIST does not mandate `CVSS × EPSS × Asset Criticality` or any equivalent formula.
- NIST does not define RBVM’s numeric weights or thresholds.

### 2.2 NIST IR 8286D Update 1

Official source: https://csrc.nist.gov/pubs/ir/8286/d/upd1/final

NIST IR 8286D extends BIA concepts to help identify mission-essential functions, critical/sensitive assets, impact values, and protection requirements.

**Useful for RBVM**

- Customer asset importance should be organization-owned evidence.
- Business impact should be derived from repeatable organizational analysis, not inferred from CVSS, KEV, EPSS, hostname, or vulnerability count.
- Asset categorization and impact values should remain auditable and revisable.

### 2.3 FIRST CVSS

Official source: https://www.first.org/cvss/

Current official major version: CVSS v4.0. RBVM currently ingests independent CVSS v3.1 Base evidence for compatibility and preserves the version/vector/source.

CVSS is a vulnerability-severity system. It is not organizational risk by itself.

**Useful for RBVM**

- A normalized technical-severity signal.
- Vector-level provenance and repeatability.
- Strong separation between intrinsic vulnerability characteristics and environmental/business context.

**Do not infer**

- `CVSS = Risk`.
- `CVSS Critical = immediate remediation priority`.

### 2.4 FIRST EPSS

Official sources:

- https://www.first.org/epss/
- https://www.first.org/epss/faq.html
- https://www.first.org/epss/data.html

EPSS estimates the probability that a published CVE will be exploited in the wild in the next 30 days. The probability is the primary model output; percentile is a population-relative transformation.

FIRST explicitly states EPSS is not a complete risk score and does not know organization-specific impact, exposure, compensating controls, or applicability.

Model-version boundaries matter for historical interpretation. The EPSS data documentation identifies model changes including EPSS v5 beginning publication on 2026-06-15.

**Useful for RBVM**

- Treat EPSS probability as a probability, not an ordinal severity band unless policy explicitly defines one.
- Preserve model version, score date, publication/observation provenance.
- Never convert missing EPSS evidence to zero.

### 2.5 CISA Known Exploited Vulnerabilities

Official source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

CISA describes KEV as the authoritative source of vulnerabilities known to have been exploited in the wild and recommends it as an input to vulnerability-management prioritization.

**Useful for RBVM**

- Explicit evidence that exploitation has been observed in the wild.
- A strong categorical threat signal.

**Do not infer**

- `NOT_LISTED = not exploitable`.
- `LISTED = complete organizational risk result`.
- CISA due dates are not customer SLA unless a separate policy adopts them.

### 2.6 CERT/SEI SSVC 2.0

Official source: https://insights.sei.cmu.edu/library/prioritizing-vulnerability-response-a-stakeholder-specific-vulnerability-categorization-version-20/

SSVC is a modular decision-tree approach for vulnerability response. It deliberately avoids treating one universal numeric score as the only way to prioritize action. Stakeholder context matters, and the applier perspective considers factors such as exploitation, exposure, and mission impact.

**Useful for RBVM**

- Explicit decision points are highly explainable.
- Missing or unresolved decision points can remain unresolved instead of being silently assigned neutral weights.
- Policy output can be separate from risk measurement.

**Key architectural lesson**

RBVM should keep `Risk Result` and `Priority / Treatment Decision` as separate contracts. An SSVC-like policy may ultimately be more appropriate for Priority than for the Formula itself.

### 2.7 OWASP Risk Rating Methodology

Official source: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

OWASP presents the common qualitative framing `Risk = Likelihood × Impact`, with multiple threat-agent, vulnerability, technical-impact, and business-impact factors. The current OWASP page includes a disclaimer noting long-running debate about parts of the methodology and points users to other mature risk methods.

**Useful for RBVM**

- Likelihood and impact should be independently understandable.
- Business impact can change the practical meaning of technical impact.
- A model should be customizable and transparent about assumptions.

**Do not copy**

- OWASP’s historical 0–9 factor weights as RBVM truth.
- AppSec-specific threat-agent factors that RBVM cannot evidence reproducibly.

### 2.8 MITRE CWSS 1.0

Official source: https://cwe.mitre.org/cwss/cwss_v1.0.html

CWSS scores software weaknesses using three groups: Base Finding, Attack Surface, and Environmental. Its final score is the Base Finding subscore multiplied by Attack Surface and Environmental subscores.

**Useful for RBVM**

- Demonstrates a structured distinction among intrinsic weakness characteristics, attack surface, and environment.
- Shows how a multiplicative model can behave like gating/modulation rather than simple additive points.
- Explicitly includes business impact and external control effectiveness concepts.

**Limitations for RBVM**

- CWSS is oriented toward software weakness findings, not RBVM’s CVE-on-asset Decision Input.
- It is an older model and its published default weights must not be adopted without validation.
- CWSS assigns numeric values to `Unknown`; RBVM currently rejects that pattern because `MISSING / AMBIGUOUS / STALE` are first-class states, not neutral numbers.

### 2.9 Open FAIR

Official source: https://www.opengroup.org/open-fair

Open FAIR provides a quantitative information-risk taxonomy and analysis method. It focuses on measurable/estimated frequency and loss magnitude and supports expressing risk in economic terms.

**Useful for RBVM**

- Strong reference for what genuinely quantitative risk means.
- Encourages calibrated estimates, uncertainty, and business-aligned outputs.
- Demonstrates why a severity/prioritization score should not be casually labeled quantitative financial risk.

**Current RBVM limitation**

The current seven Decision Input dimensions do not include sufficient data to claim Open-FAIR-style economic risk quantification. RBVM must not label a future 0–100 or 0–1000 score as expected financial loss.

## 3. Vendor-model benchmark

Vendor models are useful for product behavior and factor selection, but they are not normative standards. RBVM must not reverse-engineer or copy proprietary weights.

### 3.1 Tenable Vulnerability Priority Rating / Unified Risk Scoring

Official sources:

- https://docs.tenable.com/vulnerability-management/best-practices/security/Content/VulnerabilityPriorityRating.htm
- https://docs.tenable.com/release-notes/Content/vulnerability-management/2026.htm

Tenable VPR combines technical impact with threat information. Current 2026 release notes describe a transition toward Unified Risk Scoring.

**Benchmark lesson**

- Dynamic threat context materially changes prioritization beyond static CVSS.
- Driver-level explanation matters.

**RBVM rule**

Do not copy VPR values/formulas or vendor-generated threat factors that RBVM cannot independently evidence.

### 3.2 Qualys TruRisk

Official source: https://docs.qualys.com/en/etm/latest/appendix/calculating_trurisk_score.htm

Qualys documents models that combine asset criticality with vulnerability/detection scores, threat indicators, exposure, and asset-level aggregation. Public documentation includes several formula variants and configurable/proprietary weights.

**Benchmark lesson**

- Asset criticality and external exposure can materially modulate risk.
- Aggregating many findings at asset/tag level introduces dilution/inflation problems that require explicit policy.
- Explainability requires showing contributing factors, not only the total score.

**RBVM rule**

RBVM V1 Formula should evaluate one canonical Finding/Decision Input before any separate asset/portfolio aggregation contract is designed.

### 3.3 Rapid7 Active Risk

Official source: https://docs.rapid7.com/insightvm/working-with-risk-strategies-to-analyze-threats

Active Risk is Rapid7’s recommended 0–1000 vulnerability risk strategy. It combines the latest available CVSS with exploit/threat intelligence, including exploit availability and exploitation-in-the-wild signals. Rapid7 deprecated older legacy risk strategies on 2026-01-21.

**Benchmark lesson**

- Threat-aware vulnerability scoring is operationally useful.
- Risk-strategy/version history matters because changing methodology changes trend interpretation.
- Historical scores cannot always be recalculated after methodology changes.

**RBVM rule**

Formula ID/version/hash and exact Decision Input references must be persisted so historical results remain reproducible under the methodology actually used at the time.

## 4. Cross-model patterns

Across the references, recurring concepts are:

1. **Intrinsic technical severity is not complete risk.**
2. **Likelihood/threat and impact are distinct concepts.**
3. **Real-world exploitation materially changes urgency.**
4. **Environment/exposure matters.**
5. **Business/mission context matters.**
6. **One global numeric score is not always the best treatment policy.**
7. **Aggregation is a separate problem from per-finding evaluation.**
8. **Explainability and methodology versioning are necessary for trustworthy historical comparison.**
9. **Unknown data must be handled deliberately.**
10. **A score is not automatically an SLA or remediation action.**

These patterns align with RBVM’s existing evidence-first architecture, but they do not select a specific V24 formula.

## 5. Models intentionally not adopted by this atlas

This atlas does not authorize:

- a direct copy of any vendor score;
- hidden thresholds such as `EPSS >= X => High Risk`;
- converting KEV membership directly into a final risk tier;
- using scanner-reported severity as official CVSS;
- treating missing evidence as zero, false, low, or safe;
- averaging independent evidence dimensions merely because they can be normalized;
- asset- or portfolio-level aggregation before a separate aggregation contract exists;
- calling a qualitative 0–100 score “financial risk” without a quantitative loss model;
- converting Risk directly to SLA or Priority without a separate treatment policy.

## 6. Atlas conclusion

The strongest direction for RBVM is **not** to choose one external formula. The platform should design a transparent finding-level contract that:

- consumes the exact immutable Decision Input snapshot;
- preserves source semantics instead of flattening them prematurely;
- has explicit treatment of missing/stale/ambiguous evidence;
- separates technical severity, exploitation likelihood/evidence, exposure, and impact;
- has no hidden source winner or implicit customer context;
- produces an explainable Risk Result;
- leaves Priority, remediation, SLA, and portfolio aggregation to later contracts.

The next required document is `RBVM_FORMULA_READINESS_V1`.
