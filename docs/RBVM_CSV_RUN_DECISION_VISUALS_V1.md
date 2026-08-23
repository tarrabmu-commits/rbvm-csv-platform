# RBVM CSV Run Decision Visuals V1

Contracts:

- `CSV_RUN_DECISION_VISUALS_V1`
- `CSV_RUN_DECISION_VISUALS_MOUNT_V1`

Priority authority:

- `RBVM_MVP_PRIORITY_POLICY_V1`
- SHA-256 `88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388`

## Purpose

The CSV Run Decision Dashboard is the deep visual layer for one exact immutable contextual-analysis revision.

Unlike the canonical Overview, this screen has the exact row-level inputs and outputs needed to visualize the MVP treatment-priority policy without inference. It reloads the already-published immutable priority CSV, priority report, and method-admission report. The browser does not reproduce the priority algorithm.

## Visual model

### Pareto priority distribution

A donut shows:

- Front 1;
- Front 2;
- later Pareto fronts if present;
- Unrankable.

`Front 1` means nondominated **within the exact input set**. It is not a Critical/High risk label, SLA, or Organizational Risk level.

### Unrankable evidence blockers

A ranked horizontal bar view uses the server-emitted `unrankableReasons` or row blocker codes. It shows which mandatory MVP dimensions are missing or invalid:

- CISA KEV state;
- customer Internet Facing;
- customer Asset Criticality;
- FIRST EPSS probability;
- contextual CVSS v4 score.

Missing evidence is never visualized as zero.

### Contextual CVSS v4 × EPSS scatter

The chart places each row using:

- X: native FIRST EPSS probability;
- Y: contextual CVSS v4 technical-severity score.

CISA KEV-listed rows are highlighted and Front 1 rows receive an outer ring.

The two axes remain independent evidence dimensions. The visualization does **not** multiply CVSS and EPSS, draw a synthetic risk boundary, or introduce local thresholds.

### Pareto dominance landscape

A second scatter plot uses only server-emitted policy outputs:

- X: rows dominated by the finding;
- Y: rows dominating the finding;
- marker class: emitted Pareto front.

This is explainability of the already-computed dominance relationship. It does not create a second priority score and does not reorder findings within a front.

### CISA SSVC evidence profile

CISA Vulnrichment SSVC evidence is grouped separately by its published row fields:

- Exploitation;
- Automatable;
- Technical Impact.

RBVM does not infer `Track`, `Track*`, `Attend`, or `Act` from these fields. An SSVC decision chart may be added only when an explicit decision output and its provenance are available.

### Customer context matrix

A heatmap shows direct customer declarations already associated with each analysis row:

- Asset Criticality;
- Internet Facing.

This association is defensible because both fields belong to the exact matched row. `Internet Facing` remains asset-level context and is not exact endpoint/Finding reachability.

### CVSS v4 context modes

A donut shows the contextual nomenclature produced for the run, including forms such as:

- `CVSS-B`;
- `CVSS-BT`;
- `CVSS-BE`;
- `CVSS-BTE`;
- unavailable.

The chart is technical-severity provenance, not Organizational Risk.

### CVSS v4 Security Requirements

Stacked profile bars show the direct customer values for:

- Confidentiality Requirement (CR);
- Integrity Requirement (IR);
- Availability Requirement (AR).

The native `H/M/L/X` values are displayed directly. Asset Criticality is not converted into CR/IR/AR.

### Organizational Risk method admission

Candidate methods are shown with their categorical admission state and the number of Organizational Risk rows they actually computed.

The dashboard does not rank method candidates by list order, display order, score magnitude, or vendor identity.

## Read-only mounting

The mount module derives `runId` from the current CSV-first route and the immutable `analysisId` from the review contract already displayed to the operator. It then reads:

- `/api/v1/csv-first-priorities/{runId}/{analysisId}/csv`
- `/api/v1/csv-first-priorities/{runId}/{analysisId}/report`
- `/api/v1/csv-first-enrichments/{runId}/analyses/{analysisId}/method-admission`

No new calculation endpoint or source-of-truth store is introduced.

## Missing-evidence protection

Before chart rendering, blank EPSS values, unavailable contextual CVSS values, and missing Pareto relationship counts are normalized to explicit non-numeric `MISSING` markers. This prevents JavaScript numeric coercion from turning an empty string into `0`.

## Standards alignment

The visualization architecture follows the project’s standards mapping:

- **FIRST CVSS v4** — contextual technical severity is shown as technical severity, not risk;
- **FIRST EPSS** — native exploitation probability remains independent and no local standard threshold is invented;
- **CISA KEV** — confirmed exploitation evidence is highlighted without treating non-listing as safety;
- **CISA SSVC / Vulnrichment** — decision inputs remain separate and no action outcome is inferred;
- **NIST CSF 2.0** — the dashboard supports current exposure/risk understanding and communication;
- **NIST IR 8286 family** — mission/customer context remains distinguishable from technical vulnerability evidence;
- **NIST SP 800-40 Rev. 4** — treatment and remediation claims require defensible lifecycle evidence rather than presentation-layer inference.

## Explicit non-claims

CSV Run Decision Visuals V1 does not:

- calculate Organizational Risk;
- calculate a new treatment-priority score;
- re-run Pareto nondominated sorting in the browser;
- multiply CVSS by EPSS;
- introduce hidden weights or thresholds;
- convert KEV non-listing into `not exploitable`;
- infer an SSVC action decision;
- convert Internet Facing into exact reachability;
- convert Asset Criticality into CVSS CR/IR/AR;
- convert CISA due dates into a customer SLA;
- fabricate remediation history.
