# RBVM Derived Risk Methodology Comparison UI V1

Status: `IMPLEMENTED_PRESENTATION_ONLY`

Contract marker: `DERIVED_RISK_METHODOLOGY_COMPARISON_UI_V1`

## Purpose

Frontend System V2 presents replay-verified derived-risk methodologies inside the existing Case/Finding investigation drawer without inventing a new risk model, a preferred methodology, or a cross-methodology score.

The browser presentation consumes the exact HTTP contracts introduced for Decision Input V3 and V24 derived-risk results. It does not perform methodology evaluation itself.

## Finding scope

A Case can contain multiple component-specific Findings. The Risk Methodologies tab therefore starts from explicit `findingId` values already returned in the Case detail payload.

The UI never derives a Finding identity from CVE, Case ID, asset name, component text, product name, or array position. If no canonical Finding ID is available, methodology comparison is unavailable rather than inferred.

## Exact Decision Input selection

For one selected Finding the UI reads:

```text
GET /api/v1/findings/{findingId}/decision-input-snapshots?limit=100
```

Only `RBVM_DECISION_INPUT_SNAPSHOT_V3` rows are eligible for derived-risk evaluation.

Snapshot history ordering is pagination-only. The UI deliberately renders an empty selection first:

```text
Select exact Decision Input V3 snapshot…
```

It never treats the first row as `latest`, `current`, or preferred. The operator must explicitly select one immutable snapshot SHA before any derived-risk result is read or materialized.

The selected snapshot view preserves its exact SHA-256, evaluation time, Decision Methodology revision/policy SHA, and `PRESENT / MISSING / AMBIGUOUS / STALE` dimension states.

## Methodology discovery

The UI reads:

```text
GET /api/v1/derived-risk-methodologies
```

and requires:

```text
selectionSemantics = EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT
```

Methodology cards are displayed side-by-side for comparison. Display order carries no precedence or preference semantics.

There is intentionally no browser-only "primary methodology" selector in V1. A primary/preferred methodology is a decision-policy concept that requires its own auditable persistence and provenance contract; an ephemeral browser preference would not satisfy that requirement.

## Exact result reads

For the one explicitly selected snapshot, each methodology is read by the full immutable tuple:

```text
GET /api/v1/derived-risk-results
  ?inputSnapshotSha256={snapshotSha256}
  &methodologyId={canonicalMethodologyId}
  &methodologySha256={methodologySha256}
```

A successful result presents:

- exact methodology ID/version/SHA;
- methodology-native `resultState`;
- native numeric score and native scale only for `COMPUTED`;
- native rating when that methodology contract defines one;
- terminal reason for `NOT_APPLICABLE` or `NON_COMPUTABLE`;
- canonical result SHA-256;
- replay-verification state;
- persisted time; and
- methodology-native intermediate measures.

The UI never converts terminal states to zero or another numeric value.

## Explicit materialization

A `404` exact-result read means no result has been persisted for that exact snapshot/methodology tuple. It does not mean zero risk or a negative result.

An Operator may explicitly request:

```text
POST /api/v1/derived-risk-result-materializations/
  {inputSnapshotSha256}/{methodologyId}/{methodologySha256}
```

with no body and no query selector. The UI uses exactly the snapshot and methodology identities already visible to the operator. Viewer-only callers receive the backend `403` rather than silently escalating or substituting another operation.

## Comparison semantics

OWASP-derived and Microsoft Probability×Damage-derived results have different native ranges and rating semantics. V1 therefore does **not**:

- average methodology scores;
- normalize them onto a common browser scale;
- rank one methodology above another;
- convert Microsoft output into OWASP severity bands;
- invent a common High/Medium/Low taxonomy;
- select a default/preferred/primary methodology;
- derive Priority, Treatment, SLA, remediation deadline, or remediation ranking.

The shared exact Decision Input snapshot is the comparison anchor. The individual methodology contracts remain authoritative for their own output semantics.

## Frontend integration

The feature is a progressive enhancement of the existing Frontend System V2 Finding drawer. All legacy entry-point HTML resources remain byte-identical so `/`, `/cvss`, `/kev`, `/epss`, `/asset-context`, `/reachability`, `/business-impact`, `/assets`, and `/asset-links` continue to expose the same SPA host.

The browser stores no methodology choice, snapshot choice, API credential, or result in `localStorage` or `sessionStorage`.

## Verification

`scripts/verify-derived-risk-ui.py` fails the repository verification if the UI introduces implicit snapshot/methodology selection, `latest/current` selectors, score arithmetic/ranking, hidden priority/SLA/treatment semantics, browser storage, or shared-host drift.
