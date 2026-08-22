# RBVM Decision Methodology V1

`RBVM_DECISION_METHODOLOGY_V1` defines the policy boundary between the completed independent Evidence Foundation and any later RBVM decision formula.

This increment does **not** calculate risk, priority, remediation SLA, treatment, monetary loss, or an aggregate impact score. It defines source/freshness evidence-selection policy and makes missing, ambiguous, stale, and legacy behavior explicit before any formula is introduced.

> **Decision Input V3 clarification:** source/freshness selection is applied only after Finding-context eligibility has been established. For Network Reachability and Business/Mission Impact, matching the Finding asset is necessary but not sufficient. An explicit customer-confirmed Finding association must first admit the exact Reachability scope or Business Service. This clarification does not change the V1 methodology canonical payload, fields, revision, or SHA-256 semantics; association provenance is a separate Decision Input binding layer.

## Contract

- Contract ID: `RBVM_DECISION_METHODOLOGY_V1`
- Semantics: `FINDING_SCOPED_EXPLICIT_EVIDENCE_SELECTION_POLICY`
- Evaluation subject: canonical `Finding_ID`
- Policy revision: positive integer
- Policy provenance: lowercase SHA-256 of the canonical policy payload defined below
- Missing evidence: `PRESERVE_UNKNOWN`
- Ambiguous multi-source evidence: `PRESERVE_AMBIGUOUS`
- Legacy `rbvm.vulnerability.priority_tier`: `EXCLUDE_LEGACY_PRIORITY_TIER`

## Canonical policy payload and SHA-256

`policySha256` is **not** hashed as part of itself. Its value is the SHA-256 of deterministic canonical binary policy bytes that exclude the `policySha256` field.

Canonical payload format identifier:

`RBVM_DECISION_METHODOLOGY_CANONICAL_BINARY_V1`

The payload encodes, in order:

1. canonical payload format identifier;
2. contract ID and contract semantics;
3. revision;
4. subject scope;
5. missing-evidence handling;
6. ambiguity handling;
7. legacy-priority handling;
8. all seven evidence-selection policies in the fixed `EvidenceDimension` enum order.

Strings are encoded as length-prefixed UTF-8. Each selection policy encodes source-selection mode, freshness mode, optional maximum age, and the source allowlist. `policySha256` itself is excluded, preventing circular provenance.

`EXPLICIT_ALLOWLIST` is semantically a set, not a precedence list. Source identifiers are trimmed, kept case-sensitive, deduplicated, and then sorted lexicographically before canonical encoding. Therefore changing only the input ordering of the same allowlist does not change `policySha256`.

Constructing a policy with a supplied SHA that does not match these canonical bytes is invalid. `RbvmDecisionMethodologyPolicy.create(...)` derives the SHA from the canonical payload automatically.

## Why the grain is Finding_ID

The independent evidence dimensions converge without hidden Case aggregation at the canonical Finding grain:

| Evidence dimension | Native scope | Finding eligibility/join |
|---|---|---|
| Applicability | Finding | direct `Finding_ID` |
| Technical Severity / CVSS | CVE | finding CVE |
| Known Exploitation / KEV | CVE | finding CVE |
| Exploitation Probability / EPSS | CVE | finding CVE |
| Asset Context | Asset / explicitly linked Managed Asset | finding asset and, for Managed Asset context, exact scanner↔managed-asset binding |
| Network Reachability | Asset + origin + endpoint | finding asset **and exact effective Finding↔Reachability Scope association** |
| Business/Mission Impact | Asset + Business Service + dimension | finding asset **and exact effective Finding↔Business Service association** |

A Case can contain multiple component-level findings for the same asset+CVE. Case-level roll-up therefore remains a later explicit policy layer. V1 must not silently collapse finding-scoped Applicability or multiple scoped Reachability/Impact observations into one Case verdict.

### Association eligibility is before source selection

For Decision Input V3, the two scoped context families use this ordering:

1. resolve the canonical Finding and scanner asset;
2. resolve append-only Finding association history as-of the explicit evaluation time;
3. retain only effective `LINKED` Reachability scopes / Business Services;
4. match native evidence on the same scanner asset and exact associated target/service;
5. apply this methodology's source allowlist, per-source history reduction, freshness, and ambiguity rules.

The association event is binding provenance, not replacement evidence. A link does not fabricate `REACHABLE`, an impact level, or any other native value. `UNLINKED` and never-assessed association state both prevent an unrelated native row from entering the candidate set; neither creates negative evidence.

The association contract/version/event identifiers are recorded by the Decision Input snapshot rather than added to the methodology policy payload. Therefore this eligibility layer does **not** create a hidden source winner and does **not** require a methodology revision/SHA change when the source/freshness policy itself is unchanged.

## Required evidence policies

Every methodology artifact must contain one `EvidenceSelectionPolicy` for each of these dimensions:

1. `APPLICABILITY`
2. `TECHNICAL_SEVERITY`
3. `KNOWN_EXPLOITATION`
4. `EXPLOITATION_PROBABILITY`
5. `ASSET_CONTEXT`
6. `NETWORK_REACHABILITY`
7. `BUSINESS_MISSION_IMPACT`

Omitting a dimension is invalid. Explicit policy is required even when the intended behavior is to retain all eligible sources without an age limit.

## Source selection

Each dimension chooses one of two source-selection modes:

- `ALL_SOURCES`: all admissible **and context-eligible** evidence remains available to the decision-input snapshot;
- `EXPLICIT_ALLOWLIST`: only exact source identifiers in the policy are admissible after context eligibility has been established.

An allowlist is a filter, **not source precedence**. If more than one allowed source supplies usable evidence for an eligible sub-grain, both remain. V1 has no source winner and no ordering that silently selects one source.

The platform preserves source identifiers exactly after surrounding whitespace removal. It does not lowercase or otherwise reinterpret an evidence source in the methodology policy. Canonical lexicographic sorting is used only to make set-equivalent allowlists hash identically; it does not create precedence.

## Freshness

Freshness is an evidence-eligibility rule, not a risk weight:

- `NO_AGE_LIMIT`: the policy does not reject evidence by age;
- `MAX_AGE_SECONDS`: evidence older than the explicit positive maximum age is classified as stale by the decision-input builder.

The methodology contract does not specify a default freshness window. A decision-input snapshot evaluates age relative to an explicit evaluation time and records which observed-at timestamp was used.

## Missing and ambiguous evidence

V1 deliberately provides only these behaviors:

- missing evidence remains `UNKNOWN`/`MISSING` at the appropriate contract boundary;
- multiple admissible sources that cannot be reduced without an explicit later rule remain `AMBIGUOUS`.

Missing CVSS is not zero. Missing EPSS is not probability zero. Missing KEV is not `NOT_LISTED`. Missing Reachability is not `NOT_REACHABLE`. Missing Business Impact is not `LOW`, `NEGLIGIBLE`, or `UNKNOWN` evidence fabricated as a row.

Likewise, absence of a Finding-context association is not evidence that a target is unreachable or a service has low impact. It means the scoped native evidence is not eligible for that Finding under the current binding provenance.

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
- Case-level aggregation;
- automatic Finding↔Reachability or Finding↔Business Service inference.

## Implementation layering

The current implementation keeps these layers separate and auditable:

1. immutable/versioned Decision Methodology policy with canonical SHA-256 provenance;
2. explicit Finding-context association histories for scoped context eligibility;
3. immutable Decision Input snapshots, with V3 recording exact association-event bindings for Reachability and Business/Mission Impact;
4. exact native evidence resolution from snapshot UUID/SHA/source/time plus binding provenance;
5. a future Formula Contract that may consume only the explicit resolved Decision Input contract;
6. later Decision persistence/API and separate Priority/Treatment/SLA policy layers.

This sequencing ensures a future result can explain exactly which native evidence, association event, policy revision, freshness rule, and source-selection rule produced its input state.
