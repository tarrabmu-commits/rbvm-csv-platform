# RBVM Decision Input Snapshot Builder — Evidence Selection Semantics

This increment defines deterministic policy-aware evidence selection before the PostgreSQL builder exists. It consumes native evidence metadata and produces one typed `PRESENT|MISSING|AMBIGUOUS|STALE` dimension selection. It does not calculate an RBVM score, priority, SLA, treatment, or Case roll-up.

## Evaluation boundary

A builder evaluation is always explicit:

`Finding_ID + exact methodology revision/SHA + evaluatedAt`

The builder must never choose `current`, `active`, `highest`, or `max(revision)` methodology implicitly. Native candidates must be queried **as-of `evaluatedAt`**; evidence observed after that time is not admissible.

## Source filtering

The dimension's `EvidenceSelectionPolicy` is applied exactly:

- `ALL_SOURCES`: all semantic evidence sources are admissible;
- `EXPLICIT_ALLOWLIST`: only exact allowlisted source identifiers are admissible;
- allowlist order has no precedence meaning;
- filtering a source out does not turn its evidence into negative evidence.

## History reduction

Native evidence history must not itself create ambiguity. For each:

`sub-grain + semantic source`

select only the latest admissible `observedAt <= evaluatedAt` row. Older rows are history and remain outside the Decision Input Snapshot reference set.

If the same source and same sub-grain have multiple distinct native evidence rows tied at the latest timestamp, the tie remains unresolved and the sub-grain is ambiguous. The selector must not choose by UUID, ingestion order, severity, or value.

## Source-independent sub-grains

A sub-grain deliberately excludes evidence source so independently allowed sources can be compared for the same semantic subject.

| Evidence dimension | Builder sub-grain |
|---|---|
| `APPLICABILITY` | canonical `Finding_ID` |
| `TECHNICAL_SEVERITY` | canonical vulnerability/CVE identity referenced by the Finding |
| `KNOWN_EXPLOITATION` | canonical vulnerability/CVE identity referenced by the Finding |
| `EXPLOITATION_PROBABILITY` | canonical vulnerability/CVE identity referenced by the Finding |
| `ASSET_CONTEXT` | canonical `Asset_ID` referenced by the Finding |
| `NETWORK_REACHABILITY` | `Asset_ID + Origin_Scope + normalized Origin_Label + Transport_Protocol + Target_Port` |
| `BUSINESS_MISSION_IMPACT` | `Asset_ID + normalized Business_Service + Impact_Dimension` |

These keys describe semantic grouping only. The PostgreSQL builder may use typed columns rather than concatenated strings, but its grouping must be equivalent and collision-free.

### Why Reachability and Business Impact are different

Multiple Reachability endpoints or multiple Business Impact dimensions are normal independent evidence. Therefore:

- TCP/443 and TCP/22 rows do **not** make Network Reachability ambiguous merely because both exist;
- `payments + AVAILABILITY` and `payments + INTEGRITY` do **not** make Business Impact ambiguous merely because both exist;
- ambiguity exists when multiple latest admissible evidence rows compete **inside the same sub-grain** after source filtering and history reduction.

## Freshness

Freshness is applied only to the selected latest rows:

- `NO_AGE_LIMIT`: selected rows are not stale by age;
- `MAX_AGE_SECONDS`: a selected row is stale when `evaluatedAt - observedAt` is strictly greater than the configured maximum age;
- a row exactly on the age boundary is still fresh;
- stale evidence is retained as an immutable reference rather than silently dropped.

## Dimension state precedence

`RBVM_DECISION_INPUT_SNAPSHOT_V1` has one state per evidence dimension, so mixed sub-grain conditions require deterministic precedence:

1. no selected references → `MISSING`;
2. any selected sub-grain is ambiguous → `AMBIGUOUS`;
3. otherwise, any selected reference is stale → `STALE`;
4. otherwise → `PRESENT`.

`AMBIGUOUS` intentionally takes precedence over `STALE`. Stale timestamps remain in the referenced evidence and freshness remains reproducible from the immutable methodology policy + `evaluatedAt`; ambiguity must not be hidden by age classification.

## Native-reference integrity

The later PostgreSQL builder must construct candidates directly from native tenant-scoped evidence rows. Every candidate must carry the native:

- evidence UUID;
- evidence-row SHA-256;
- semantic source;
- observation/evaluation timestamp;
- source-independent sub-grain fields.

External callers must not be allowed to supply arbitrary evidence UUID/SHA tuples to the builder.

## Deliberate boundary

The selector never inspects native evidence **values** to choose a winner. It does not select higher CVSS, `LISTED` KEV, larger EPSS, `MISSION_CRITICAL`, `REACHABLE`, `SEVERE`, or any other value as preferable. It uses only explicit methodology source/freshness rules, time, and semantic sub-grain identity.

No weight, multiplier, coefficient, threshold, numeric risk score, priority tier, SLA, treatment decision, monetary loss model, attack-path score, or source ranking is defined here.