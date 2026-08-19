# RBVM Decision Methodology V1

`RBVM_DECISION_METHODOLOGY_V1` defines the policy boundary between the completed independent Evidence Foundation and any later RBVM decision formula.

This increment does **not** calculate risk, priority, remediation SLA, treatment, monetary loss, or an aggregate impact score. It defines which evidence is eligible to become a decision input and makes missing, ambiguous, stale, and legacy behavior explicit before any formula is introduced.

## Contract

- Contract ID: `RBVM_DECISION_METHODOLOGY_V1`
- Semantics: `FINDING_SCOPED_EXPLICIT_EVIDENCE_SELECTION_POLICY`
- Evaluation subject: canonical `Finding_ID`
- Policy revision: positive integer
- Policy provenance: exact lowercase SHA-256 of the serialized policy artifact
- Missing evidence: `PRESERVE_UNKNOWN`
- Ambiguous multi-source evidence: `PRESERVE_AMBIGUOUS`
- Legacy `rbvm.vulnerability.priority_tier`: `EXCLUDE_LEGACY_PRIORITY_TIER`

## Why the grain is Finding_ID

The independent evidence dimensions converge without hidden aggregation at the canonical finding grain:

| Evidence dimension | Native scope | Finding join |
|---|---|---|
| Applicability | Finding | direct `Finding_ID` |
| Technical Severity / CVSS | CVE | finding CVE |
| Known Exploitation / KEV | CVE | finding CVE |
| Exploitation Probability / EPSS | CVE | finding CVE |
| Asset Context | Asset | finding asset |
| Network Reachability | Asset + origin + endpoint | finding asset |
| Business/Mission Impact | Asset + Business Service + dimension | finding asset |

A Case can contain multiple component-level findings for the same asset+CVE. Case-level roll-up therefore remains a later explicit policy layer. V1 must not silently collapse finding-scoped Applicability or multiple scoped Reachability/Impact observations into one Case verdict.

## Required evidence policies

Every methodology artifact must contain one `EvidenceSelectionPolicy` for each of these dimensions:

1. `APPLICABILITY`
2. `TECHNICAL_SEVERITY`
3. `KNOWN_EXPLOITATION`
4. `EXPLOITATION_PROBABILITY`
5. `ASSET_CONTEXT`
6. `NETWORK_REACHABILITY`
7. `BUSINESS_MISSION_IMPACT`

Omitting a dimension is invalid. Explicit policy is required even when the intended behavior is to retain all current sources without an age limit.

## Source selection

Each dimension chooses one of two source-selection modes:

- `ALL_SOURCES`: all admissible current evidence remains available to the later decision-input snapshot;
- `EXPLICIT_ALLOWLIST`: only exact source identifiers in the policy are admissible.

An allowlist is a filter, **not source precedence**. If more than one allowed source supplies usable evidence, both remain. V1 has no source winner and no ordering that silently selects one source.

The platform preserves source identifiers exactly after surrounding whitespace removal. It does not lowercase or otherwise reinterpret an evidence source in the methodology policy.

## Freshness

Freshness is an evidence-eligibility rule, not a risk weight:

- `NO_AGE_LIMIT`: the policy does not reject evidence by age;
- `MAX_AGE_SECONDS`: evidence older than the explicit positive maximum age will later be classified as stale by the decision-input builder.

The methodology contract does not specify a default freshness window. A future decision-input snapshot must evaluate age relative to an explicit evaluation time and record which observed-at timestamp was used.

## Missing and ambiguous evidence

V1 deliberately provides only these behaviors:

- missing evidence remains `UNKNOWN`;
- multiple admissible sources that cannot be reduced without an explicit later rule remain `AMBIGUOUS`.

Missing CVSS is not zero. Missing EPSS is not probability zero. Missing KEV is not `NOT_LISTED`. Missing Reachability is not `NOT_REACHABLE`. Missing Business Impact is not `LOW`, `NEGLIGIBLE`, or `UNKNOWN` evidence fabricated as a row.

## Legacy priority policy

PostgreSQL V7 introduced `rbvm.vulnerability.priority_tier` for an older compatibility policy:

- KEV -> `IMMEDIATE`;
- EPSS >= 0.10 or CVSS >= 9.0 -> `URGENT`;
- EPSS >= 0.01 or CVSS >= 7.0 -> `HIGH`;
- otherwise `STANDARD` when enriched.

That field remains part of historical compatibility behavior, but it is **not an input** to `RBVM_DECISION_METHODOLOGY_V1`. A future RBVM decision must derive from independently persisted evidence and a versioned methodology policy, not from the legacy pre-combined tier.

## Deliberate non-goals

This contract contains no:

- risk score or probability-of-loss formula;
- numeric evidence weights, multipliers, coefficients, or risk thresholds;
- priority tier mapping;
- remediation or treatment SLA;
- monetary-loss model;
- asset-wide `internetExposed` conclusion;
- attack-path score;
- Business Criticality -> Business Impact conversion;
- CVSS + KEV + EPSS + Applicability + Asset Context + Reachability + Business Impact combination formula;
- Case-level aggregation.

## Next increments

The next implementation stages should remain separate and auditable:

1. **Decision policy persistence**: immutable versioned policy artifact with SHA-256 provenance.
2. **Decision input snapshot**: one immutable snapshot per `Finding_ID + policy revision + evaluation time`, containing selected evidence references and explicit `PRESENT|MISSING|AMBIGUOUS|STALE` state per dimension.
3. **Formula contract**: only after input snapshots are stable, define and test how selected evidence becomes an RBVM decision signal.
4. **Decision persistence/API**: record methodology version, input snapshot, output, explanation, and any later Case roll-up/treatment policy.

This sequencing ensures a future score can explain exactly which evidence, policy revision, freshness rule, and source-selection rule produced it.
