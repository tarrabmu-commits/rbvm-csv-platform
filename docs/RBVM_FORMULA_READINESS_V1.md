# RBVM Formula Readiness V1

Contract ID: `RBVM_FORMULA_READINESS_V1`

This document defines the gates that must be closed before any `RBVM_FORMULA_V1` runtime is implemented. It intentionally contains **no numeric weights, thresholds, scoring equation, risk tiers, priority mapping, SLA, or remediation policy**.

The authoritative input boundary remains the immutable Decision Input Snapshot and exact native-evidence resolver already present in the platform.

## 1. Unit of evaluation

V24 Formula must evaluate **one canonical Finding through one exact Decision Input Snapshot**.

It must not start from:

- an asset aggregate,
- a CVE aggregate across assets,
- a dashboard count,
- a current-state evidence view,
- a vendor risk score,
- a report-level summary.

Any later asset, service, business-unit, or portfolio aggregation requires a separate contract.

## 2. Required input families

The current Decision Input families are:

1. Applicability
2. CVSS v3.1 technical severity
3. CISA KEV known-exploitation evidence
4. FIRST EPSS exploitation probability
5. Asset Context
6. Network Reachability
7. Business / Mission Impact

The Formula Contract may not silently add a new input family or derive customer truth from unrelated evidence.

## 3. Semantic preservation gates

Before Formula implementation, the contract must explicitly state how each input is interpreted.

### Applicability

Must define the terminal/gating behavior for:

- `APPLICABLE`
- `NOT_APPLICABLE`
- explicit assessed `UNKNOWN`
- missing/unassessed applicability evidence

The implementation must not invent a numeric score for missing applicability.

### CVSS

CVSS remains technical severity evidence. The Formula must identify which score/vector/version/source reference is consumed from the immutable Decision Input.

The Formula must not relabel CVSS itself as organizational risk.

### CISA KEV

`LISTED` means known exploitation evidence from the validated catalog snapshot.

`NOT_LISTED` means absence from that validated complete snapshot and does **not** mean not exploitable.

Missing KEV evidence is not `NOT_LISTED`.

### EPSS

EPSS probability is a 0–1 estimate of exploitation in the next 30 days as published for the referenced model/date.

The Formula must define whether it uses probability, percentile, or both. It must not use percentile merely because it appears numerically larger.

Missing EPSS evidence must not become `0`.

### Asset Context

Environment, business service, ownership, and business criticality are customer-owned contextual evidence. Any ordinal or numeric mapping must be explicit, versioned policy rather than an undocumented frontend/backend conversion.

### Reachability

Reachability evidence is scoped to its recorded origin/endpoint/source/time. The Formula must not assume that one reachable endpoint makes every Finding on the asset internet-reachable.

### Business / Mission Impact

Business Impact is scoped evidence and may exist for multiple services/dimensions/sources. The Formula must not automatically apply the highest impact on an asset to every Finding unless an explicit association/policy contract proves that relationship.

## 4. Association gate

This is a **hard blocker** before Formula V1.

The platform currently has strong Finding identity and strong scanner↔managed-asset binding, but Formula readiness additionally requires explicit semantics for applying scoped Reachability and Business Impact evidence to a specific Finding.

A Formula must not evaluate:

```text
Asset has INTERNET:443 reachable
        ↓
Every finding on asset is internet reachable
```

or:

```text
Asset supports one SEVERE-impact service
        ↓
Every finding on asset has SEVERE business impact
```

The readiness decision must choose and document one of the following patterns, or another equally explicit pattern:

- finding/component ↔ endpoint association;
- finding/component ↔ business-service association;
- explicit customer-confirmed applicability of scoped evidence;
- a conservative unresolved state that leaves the dimension `MISSING / AMBIGUOUS` until association is known.

No hostname/product/port guess may become hidden association policy.

## 5. Evidence-state gate

Every Formula input arrives with an evidence state such as:

- `PRESENT`
- `MISSING`
- `STALE`
- `AMBIGUOUS`

Before Formula V1, the contract must define behavior for every state for every dimension.

Forbidden defaults:

- `MISSING => 0`
- `STALE => latest current row`
- `AMBIGUOUS => highest numeric value`
- `AMBIGUOUS => first row`
- `MISSING KEV => NOT_LISTED`
- `MISSING EPSS => probability 0`
- `MISSING Business Impact => LOW`

A valid outcome may be an explicitly non-computable/insufficient-evidence result if the methodology requires evidence that is not available.

## 6. Controls / mitigation decision

The current seven dimensions do not contain a first-class compensating-control effectiveness input.

Before Formula V1 is finalized, the methodology review must explicitly decide whether:

1. compensating controls are outside V1 and therefore do not affect the Formula; or
2. a new versioned evidence family must be built before Formula V1.

The Formula must not infer compensating controls from reachability, asset environment, workflow status, or free-text notes.

## 7. Formula identity and reproducibility

Any future Formula artifact must have at least:

```text
formulaId
formulaVersion
canonicalRepresentation
sha256
inputContractVersion
outputScale
roundingMode
bounds
missingEvidencePolicy
staleEvidencePolicy
ambiguousEvidencePolicy
```

If it contains weights, gates, transforms, or thresholds, every value must be present in the canonical representation and therefore covered by the Formula SHA-256.

A historical Risk Result must be reproducible from:

```text
Decision Input Snapshot ID
+ exact native evidence refs
+ Methodology ID/revision/SHA
+ Formula ID/version/SHA
```

No historical recomputation may silently use a newer Formula.

## 8. Output boundary

V24 Formula output must be a **Risk Result**, not a treatment decision.

The Formula Contract must not directly emit:

- `IMMEDIATE`
- `PATCH_IN_3_DAYS`
- `SLA_30_DAYS`
- ticket owner
- remediation campaign
- accepted-risk workflow transition

Those belong to later Priority / Treatment / SLA contracts.

If a numeric risk score is selected, its semantic meaning and scale must be stated. A `0–100` or `0–1000` value must not be described as expected financial loss unless the model is actually quantitative in economic units.

## 9. Explainability gate

For every computed Risk Result, the runtime must be able to explain:

- exact Formula ID/version/SHA;
- exact Decision Input Snapshot;
- each contributing dimension;
- each source evidence state;
- each transform/weight/gate that materially affected the result;
- any reason the result was non-computable or limited by evidence quality.

The UI may summarize this explanation, but the canonical explanation must be deterministic and machine-readable.

## 10. Monotonicity and invariant tests

Before approving a Formula, define golden cases and invariants independent of implementation.

Minimum invariants to test:

1. Exact replay of the same Decision Input + Formula produces byte-equivalent canonical result semantics.
2. Changing only display labels does not change risk.
3. Missing EPSS is not equivalent to EPSS `0`.
4. Missing KEV is not equivalent to `NOT_LISTED`.
5. `AMBIGUOUS` does not silently become the most severe candidate.
6. A later unrelated managed-asset revision cannot change a historical result.
7. A later scanner-link decision cannot change a historical result.
8. A Formula version change creates a distinct result identity even for identical Decision Input.
9. Priority/SLA policy changes do not change the underlying historical Risk Result.
10. If a dimension is explicitly defined as risk-increasing, moving only that dimension to a more adverse **valid** value must not reduce the score unless the Formula documents an interaction that explains why.

## 11. Golden-case suite

Before coding the Formula, create a small versioned set of synthetic Decision Inputs covering at least:

- applicable + critical CVSS + KEV listed + high EPSS + confirmed relevant reachability + severe impact;
- applicable + critical CVSS but no KEV and low EPSS;
- medium CVSS + KEV listed + high EPSS;
- high technical severity on a low-impact isolated context;
- lower technical severity on a mission-critical externally reachable context;
- `NOT_APPLICABLE`;
- missing EPSS;
- missing Business Impact;
- stale Reachability;
- ambiguous Business Impact;
- multiple admissible Asset Context sources;
- unlinked scanner asset with missing managed context;
- historical as-of case before and after an asset/link revision.

For the first Formula proposal, expected **ordering/behavior** should be approved before exact numeric outputs are frozen.

## 12. External-model adoption rules

Based on `GLOBAL_RBVM_FORMULA_ATLAS_V1`:

- NIST provides risk-assessment framing, not RBVM numeric weights.
- CVSS is severity evidence, not risk.
- EPSS is probability evidence, not risk.
- KEV is known-exploitation evidence, not complete risk.
- SSVC is a strong reference for later Priority/Treatment policy and explainable decision trees.
- Open FAIR is a strong reference for quantitative risk semantics, but current Decision Input does not support claiming economic-loss quantification.
- OWASP/CWSS are useful structural references but their historical numeric weights are not RBVM defaults.
- Tenable, Qualys, Rapid7, and other vendor scores are benchmarks only; proprietary or vendor-specific weights must not be copied.

## 13. Readiness checklist

Formula implementation is blocked until all are `CLOSED`:

- [ ] Evaluation unit fixed to one Finding + one immutable Decision Input.
- [ ] Applicability gating semantics approved.
- [ ] EPSS probability/percentile usage approved.
- [ ] Reachability-to-Finding association semantics approved.
- [ ] Business-Impact-to-Finding association semantics approved.
- [ ] Missing/stale/ambiguous policy approved per dimension.
- [ ] Compensating-controls scope decision approved.
- [ ] Formula output semantics/scale approved.
- [ ] Formula canonical representation + SHA contract approved.
- [ ] Deterministic explanation schema approved.
- [ ] Golden cases and invariants approved.
- [ ] Explicit separation from Priority/Treatment/SLA preserved.

Until these gates are closed, `RBVM_FORMULA_V1` remains intentionally unimplemented.
