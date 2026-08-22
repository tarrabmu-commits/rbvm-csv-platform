# RBVM Formula Golden Cases V1

Contract ID: `RBVM_FORMULA_GOLDEN_CASES_V1`

Status: `PRE_FORMULA_ACCEPTANCE_CONTRACT`

Machine-readable fixture: `docs/fixtures/RBVM_FORMULA_GOLDEN_CASES_V1.json`

This contract is the final pre-implementation gate before a numeric `RBVM_FORMULA_V1` proposal may be authored. It freezes **terminal behavior, material-sensitivity expectations, arithmetic exclusions, partial-order constraints, and replay invariants** without freezing any Formula output number, weight, coefficient, threshold, or trade-off.

## 1. What the fixture is

The fixture is a generator for **Formula-consumed semantic profiles** derived from a valid `RBVM_DECISION_INPUT_SNAPSHOT_V3` boundary. It is deliberately not an importable CVSS/KEV/EPSS/Asset/Reachability/Impact evidence file and does not fabricate source provenance.

Exact native evidence UUID/SHA/source/time/vector/binding provenance remains the responsibility of Decision Input V3 and its resolver. Stage 8 tests the semantics presented to the future Formula after those exact-evidence guarantees have already been satisfied.

All decimal values in the fixture are strings so test artifacts do not introduce binary floating-point interpretation before the Formula arithmetic contract exists.

## 2. No numeric answer is approved yet

`numericOutputsFrozen = false` is mandatory throughout Stage 8.

For a future `COMPUTED` case, Stage 8 approves only that a valid Formula must eventually produce a numeric `RBVM Relative Risk Index`. The exact value is frozen only together with the canonical `RBVM_FORMULA_V1` artifact and its SHA.

For `NOT_APPLICABLE` and `NON_COMPUTABLE`, numeric output is forbidden.

## 3. Complete evidence-state matrix

The fixture parameterizes every Decision Input dimension across:

- `MISSING`
- `STALE`
- `AMBIGUOUS`

for:

1. Applicability
2. Technical Severity
3. Known Exploitation
4. Exploitation Probability
5. Asset Context
6. Network Reachability
7. Business / Mission Impact

Every generated matrix case must terminate `NON_COMPUTABLE` with the dimension/state reason code. The matrix exists specifically to prevent later Formula code from accidentally introducing a neutral zero, current-row substitution, highest-value selection, or partial-score reweighting for one dimension while other dimensions remain strict.

## 4. Explicit terminal-value cases

Stage 8 separately freezes the semantic-value gates that can occur even while a Decision Input dimension is `PRESENT`:

- Applicability `UNKNOWN` -> `APPLICABILITY_UNKNOWN`
- KEV `UNKNOWN` -> `KEV_VALUE_UNKNOWN`
- Business Criticality `UNKNOWN` -> `BUSINESS_CRITICALITY_UNKNOWN`
- Reachability `UNKNOWN` -> `REACHABILITY_VALUE_UNKNOWN`
- Business Impact `UNKNOWN` -> `BUSINESS_IMPACT_VALUE_UNKNOWN`

Applicability `NOT_APPLICABLE` remains its own terminal result state, not numeric zero.

## 5. Structural association cases

The fixture locks the Stage 7 association/reduction rules:

- more than one effective Reachability sub-grain -> `REACHABILITY_MULTI_SUBGRAIN`;
- more than one normalized Business Service -> `BUSINESS_IMPACT_MULTI_SERVICE`;
- multiple impact dimensions for exactly one Business Service remain eligible for a future `COMPUTED` result;
- an unlinked scanner asset with no independent admissible Asset Context remains `ASSET_CONTEXT_MISSING` rather than receiving invented customer context.

The future Formula cannot select `max`, `first`, `average`, most-internet-facing, or any equivalent hidden winner to bypass these cases.

## 6. Material-sensitivity pairs

Stage 8 requires a future Formula to be materially sensitive in controlled non-saturated pairs to each Formula-relevant dimension:

- higher CVSS v3.1 Base severity > lower severity;
- KEV `LISTED` > `NOT_LISTED` with everything else Formula-relevant equal;
- higher EPSS **probability** > lower probability;
- `MISSION_CRITICAL` > `LOW` Business Criticality;
- `REACHABLE` > `NOT_REACHABLE` for the same exact linked target;
- `SEVERE` > `LOW` for the same Business Service and impact dimension.

These are `GREATER_THAN`, not merely `GREATER_OR_EQUAL`, to prevent a nominally required Formula factor from silently receiving zero influence. The synthetic pairs are deliberately chosen away from the future output bounds so saturation is not a valid explanation for equality.

The sensitivity cases do **not** determine the magnitude of any difference.

## 7. Arithmetic-exclusion equality pairs

Stage 7 already excluded several fields from Formula V1 arithmetic. Stage 8 turns those decisions into equality constraints:

- changing only EPSS percentile while probability is identical -> equal Risk Result;
- changing only Environment while Business Criticality is identical -> equal Risk Result;
- changing only Business Owner -> equal Risk Result.

Those fields remain available to deterministic explanation and analytics. Equality here means they cannot change Formula V1 arithmetic.

## 8. Partial order, not total ranking

Stage 8 deliberately refuses to pre-rank cases where multiple dimensions move in opposing directions.

Two required `UNORDERED_BY_READINESS` comparisons are frozen:

1. critical technical severity + KEV not listed + low EPSS versus medium severity + KEV listed + high EPSS;
2. high technical severity + low criticality/impact + not-reachable versus lower technical severity + mission-critical/severe-impact + reachable.

Any attempt to rank these cases before the Formula artifact exists would implicitly choose weights or interactions. Their ordering is therefore a Stage 9 Formula design decision and must be visible in the canonical Formula definition.

A separate dominance case (`GC-ALL-ADVERSE`) must rank above the base profile because multiple Formula-relevant dimensions become more adverse and none improve.

## 9. Historical/replay invariants

The golden suite also freezes non-numeric identity behavior:

- later scanner-managed-asset or Finding-context association changes cannot mutate a historical result;
- later native evidence cannot replace evidence retained by the historical Decision Input;
- Formula version/SHA changes create distinct result identity even if displayed numbers happen to match;
- Priority/Treatment/SLA policy changes cannot alter the underlying Risk Result identity;
- exact Decision Input + exact Formula identity must reproduce byte-equivalent canonical result and explanation semantics.

## 10. Acceptance rule for Formula V1

A proposed `RBVM_FORMULA_V1` is not acceptable merely because it produces values in `0.00..100.00`.

Before implementation is approved, its canonical artifact and pure evaluator tests must satisfy every Stage 8 generated case, explicit case, relation, and replay invariant. Exact numeric outputs for computed golden profiles may then be frozen in a **Formula-bound expected-output artifact** whose identity includes the exact Formula SHA.

This prevents golden cases from being edited after seeing a preferred implementation output.

## 11. Stage boundary

Stage 8 contains no:

- Formula equation;
- weight;
- coefficient;
- threshold;
- numeric KEV bonus;
- numeric criticality mapping;
- numeric impact mapping;
- priority tier;
- remediation SLA;
- treatment rule.

Once this contract is merged and verified, the evidence/association/readiness/golden-case prerequisites for proposing `RBVM_FORMULA_V1` are closed. The next stage may design the Formula artifact, but it must fit these constraints rather than rewrite them.