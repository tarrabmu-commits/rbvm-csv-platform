# RBVM V2 Risk Method Admission V1

Contract ID: `RBVM_V2_METHOD_ADMISSION_V1`

## Purpose

This contract answers a narrower question than a risk formula:

> Given the evidence produced by the CSV-first CVSS v4 pipeline, which existing RBVM risk methodologies are actually admissible for execution, and which are only references or blocked candidates?

It deliberately does **not** choose a winner and does **not** create a new Organizational Risk formula.

## Why this boundary is required

RBVM currently contains several artifacts with different semantics:

- `CVSS_V4_CONTEXT_RESOLVER_V2` produces official-FIRST-compatible contextual **technical severity** (`CVSS-B`, `CVSS-BT`, `CVSS-BE`, or `CVSS-BTE`). It is not a risk methodology.
- `RBVM_FORMULA_V1` is an accepted historical `RBVM_POLICY` relative-risk index. It consumes exact `RBVM_DECISION_INPUT_SNAPSHOT_V3` evidence and uses CVSS v3.1 Base.
- `OWASP_DERIVED_RBVM_V1` is an RBVM adaptation of the published OWASP Risk Rating shape. It is `STANDARD_DERIVED`, not an official OWASP-produced score.
- `MICROSOFT_PD_DERIVED_RBVM_V1` is an RBVM adaptation of Microsoft Probability × Damage Potential. It is `STANDARD_DERIVED`, not a Microsoft-produced score.
- no `RBVM_FORMULA_V2` Organizational Risk identity has been approved.

Without an admission layer, a caller could incorrectly treat contextual CVSS as Organizational Risk, silently run a legacy method on incompatible evidence, or auto-select a derived vendor-shaped model.

## Current CSV-first evidence capability

The current CSV-first V2 pipeline can produce, per finding:

- CVE-scoped public CVSS v4 evidence with provenance;
- contextual CVSS v4 technical severity through direct customer CR/IR/AR declarations;
- FIRST EPSS probability and percentile;
- CISA KEV state from a complete catalog snapshot;
- CISA SSVC enrichment when published;
- customer Asset Criticality;
- customer asset-level Internet Facing declaration.

It does **not** currently produce the exact `RBVM_DECISION_INPUT_SNAPSHOT_V3` seven-dimension evidence boundary required by Formula V1 and both derived methods. In particular, the CSV-first contract does not currently supply:

1. first-class Applicability evidence;
2. exact Finding-associated `NETWORK_REACHABILITY_CSV_V1` evidence;
3. exact Finding-associated `BUSINESS_IMPACT_CSV_V1` evidence;
4. a Decision Input V3 snapshot binding those native evidence identities and association events.

`Internet Facing` must not substitute for exact Finding/endpoint Reachability. CR/IR/AR must not substitute for Business/Mission Impact evidence.

## Candidate classifications

### `CVSS_V4_CONTEXTUAL_SEVERITY`

Classification: `EVIDENCE_ENGINE`

Admission state: `NOT_A_RISK_METHOD`

The score is admissible as technical-severity evidence only.

### `RBVM_FORMULA_V1`

Classification: `RBVM_POLICY`

Formula SHA-256:

`88bf31f510089b4209b1ffcf1c15b39fef60548209875334f084888316e9028e`

Admission state for CSV-first V2: `LEGACY_REFERENCE_ONLY`

Reason: V1 is immutable and valid for its own exact Decision Input V3 contract, but the current CSV-first V2 run is not that input contract and must not be silently coerced into it.

### `OWASP_DERIVED_RBVM_V1`

Classification: `STANDARD_DERIVED`

Method SHA-256:

`03a72c8479e834174dc6985580d2543ad61b01628a79da5d59c5b5785e80c9c3`

Admission state for CSV-first V2: `BLOCKED_INPUT_CONTRACT`

The published outer shape is `Risk = Likelihood * Impact`, but RBVM's evidence normalization and mapping are local policy. The implemented evaluator requires exact Decision Input V3 evidence, including Applicability, exact Reachability, and Business/Mission Impact.

### `MICROSOFT_PD_DERIVED_RBVM_V1`

Classification: `STANDARD_DERIVED`

Method SHA-256:

`b22520b7b5a7d5f06782270feaf6729089ebafef79f20aea43dddf18396dcce6`

Admission state for CSV-first V2: `BLOCKED_INPUT_CONTRACT`

The published outer shape is `Risk = Probability * Damage Potential`; the RBVM mapping into Probability and Damage Potential remains explicit local policy and the evaluator requires exact Decision Input V3 evidence.

### Future `RBVM_FORMULA_V2`

Classification: `UNDEFINED`

Admission state: `METHOD_NOT_APPROVED`

No formula ID/version/SHA, canonical representation, output scale, missing-evidence policy, or calibrated thresholds exist yet. Therefore no V2 method can be selected or executed by implication.

## Admission invariants

1. Catalog presence does not imply admission.
2. Catalog order is never precedence.
3. Contextual CVSS is never promoted to Organizational Risk.
4. A method requiring `RBVM_DECISION_INPUT_SNAPSHOT_V3` cannot be executed from a CSV-first analysis row by field-name similarity.
5. `Internet Facing` cannot satisfy exact Reachability.
6. CR/IR/AR cannot satisfy Business/Mission Impact.
7. No risk method is auto-selected.
8. Any later admitted V2 method must have exact ID, version, SHA-256, canonical representation, input contract, output semantics, and explicit missing/stale/ambiguous policies.

## Machine-readable report

`scripts/evaluate-rbvm-v2-method-candidates.py` emits `RBVM_V2_METHOD_ADMISSION_REPORT_V1`.

The report records evidence coverage, exact candidate identities, admission states, blocker families, and an explicit top-level selection state. It never emits a risk number.

The expected current top-level state is:

```text
NO_V2_PRIMARY_METHOD_ADMITTED
```

This is a positive engineering result: it makes the remaining work explicit instead of converting missing semantics into an undocumented formula.
