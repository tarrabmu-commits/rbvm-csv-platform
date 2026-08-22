# Finding Context Association V1

Contracts:

- `FINDING_REACHABILITY_SCOPE_LINK_V1`
- `FINDING_BUSINESS_SERVICE_LINK_V1`

Classification: **RBVM_POLICY**

These contracts close a Formula-readiness gap without introducing a Formula. They record explicit, customer-confirmed statements about which scoped organizational/environmental context is applicable to one canonical Finding.

They do **not** calculate risk, priority, SLA, remediation order, or exploitability.

## Why this exists

A canonical Finding is scoped to:

```text
scanner source profile
+ scanner asset
+ CVE
+ component
```

Network Reachability evidence is narrower than an asset: one observation is scoped to an origin and transport endpoint.

Business/Mission Impact evidence is narrower than an asset: one observation is scoped to an asset + business service + impact dimension.

Therefore these inferences are invalid:

```text
Asset has INTERNET → TCP/443 → REACHABLE
    => every Finding on the asset is Internet reachable   ❌
```

```text
Asset has SEVERE impact for Payments
    => every Finding on the asset has SEVERE impact       ❌
```

The current pre-Formula Decision Input builder still loads those evidence families by `asset_id`. These contracts are the explicit applicability layer required before that builder can be hardened.

## Design principles

1. **Finding-specific.** A link applies to exactly one canonical Finding ID.
2. **Customer-confirmed only.** The link method is `CUSTOMER_CONFIRMED`.
3. **Append-only.** Changes are new immutable revisions, never destructive updates.
4. **Never assessed is not unlinked.** Missing history means no customer association decision has been made. `UNLINKED` is an explicit negative association decision.
5. **No heuristics.** Hostname, product name, CVSS, KEV, EPSS, target-service label, port conventions, or business criticality never create a link automatically.
6. **Stable target, refreshed evidence.** A link targets a stable scope key, not one evidence UUID. Later evidence snapshots can be selected under the same explicit target association.
7. **Evidence source remains independent.** The association does not select a winning reachability or impact evidence source. Existing Decision Methodology source/freshness/ambiguity policy remains authoritative.
8. **As-of semantics.** Later persistence must resolve the latest association revision recorded at or before the Decision Input `evaluatedAt`.
9. **Exact binding provenance.** A later Decision Input contract must retain the exact association event that authorized each scoped evidence join.

## Reachability scope link

`FINDING_REACHABILITY_SCOPE_LINK_V1` associates one Finding with one normalized reachability scope.

Stable scope key:

```text
Origin_Scope
+ normalized Origin_Label
+ Transport_Protocol
+ Target_Port
```

The values mirror `NETWORK_REACHABILITY_CSV_V1` endpoint/origin identity semantics:

- Origin scope: `INTERNET`, `EXTERNAL_PARTNER`, `INTERNAL_ENTERPRISE`, `LOCAL_SEGMENT`, `OTHER`, `UNKNOWN`.
- Transport: `TCP`, `UDP`, `ICMP`, `OTHER`, `UNKNOWN`.
- TCP/UDP require a port; ICMP forbids a port.
- Origin label is Unicode NFKC + trim + lowercase for matching.

`Target_Service` is intentionally **not** part of the association key because the reachability evidence contract treats it as source-observed content, not endpoint identity.

`Evidence_Source` is intentionally **not** part of the association key. One customer association may admit multiple independent evidence sources for the same scope; the Decision Methodology decides source admissibility and ambiguity.

Example:

```text
Finding F-1
  ↕ customer-confirmed
INTERNET | edge probe | TCP | 443
```

This allows evidence for exactly that scope to become a candidate for F-1. It says nothing about TCP/22, a partner origin, another Finding on the same asset, or global Internet exposure.

## Business service link

`FINDING_BUSINESS_SERVICE_LINK_V1` associates one Finding with one normalized business-service key.

Stable target key:

```text
normalized Business_Service
```

Normalization matches the Business Impact contract: Unicode NFKC + trim + lowercase.

The association does not choose an `Impact_Dimension` or `Impact_Source`. Once a service is explicitly linked, source-reported impact dimensions for that service remain independent sub-grains and existing methodology policy determines admissible sources/freshness/ambiguity.

Example:

```text
Finding F-1
  ↕ customer-confirmed
payments
```

This allows Business Impact evidence for `payments` to become candidates for F-1. Impact evidence for `internal-test` remains outside F-1 unless that service is independently linked.

A Finding may be linked to more than one business service when the customer explicitly confirms that scope.

## Event state

Both contracts use:

```text
LINKED
UNLINKED
```

A logical stream is identified by:

```text
Finding ID + stable target key
```

and has monotonically increasing revisions.

Examples:

```text
revision 1 → LINKED
revision 2 → UNLINKED
revision 3 → LINKED
```

The effective state as of time T is the highest revision in that stream whose `recordedAt <= T`.

No row for a stream means `never assessed`, not `UNLINKED`.

## Evidence SHA

Each immutable association event has a canonical SHA-256 over customer state, including:

- contract ID;
- Finding ID;
- revision;
- LINKED/UNLINKED state;
- stable target key;
- `CUSTOMER_CONFIRMED` method.

Authenticated actor and free-text change note are audit metadata, not customer association state. Changing only audit metadata does not create a different semantic replay identity.

## Relationship to native evidence

These links are **binding provenance**, not replacements for native evidence.

The future flow must be:

```text
Finding
  ↓ exact association event as-of evaluatedAt
Stable reachability/service target
  ↓
Native immutable Reachability / Business Impact history
  ↓ methodology source/freshness/ambiguity policy
Exact native evidence reference(s)
  + exact association event reference
  ↓
Decision Input
```

The association event cannot be used as a synthetic reachability status or impact level.

## Decision Input requirement

`RBVM_DECISION_INPUT_SNAPSHOT_V2` currently supports a binding reference only for `MANAGED_ASSET_REVISION` through `SCANNER_MANAGED_ASSET_LINK_EVENT`.

The next Decision Input increment must add explicit binding kinds for:

```text
FINDING_REACHABILITY_SCOPE_LINK_EVENT
FINDING_BUSINESS_SERVICE_LINK_EVENT
```

and must require them when V3 references:

```text
NETWORK_REACHABILITY_EVIDENCE
BUSINESS_IMPACT_EVIDENCE
```

The exact binding event ID/SHA/source/time must be covered by the Decision Input canonical hash.

## Persistence requirements for the next increment

A PostgreSQL persistence increment must provide two explicit append-only event tables rather than a generic polymorphic association table.

Required properties:

- tenant scoped;
- FK to canonical `rbvm.exposure` Finding ID;
- unique logical stream per Finding + target key;
- monotonic revision;
- exact replay idempotency;
- stale expected-revision conflict instead of overwrite;
- `SELECT + INSERT` runtime privileges only;
- no `UPDATE / DELETE / TRUNCATE` for history;
- deterministic as-of reads;
- explicit current views only as operational convenience, never for historical Decision Input build.

## Deliberate non-goals

V1 does not provide:

- automatic association suggestions that become truth;
- product-name → port mapping;
- CVE metadata → service mapping;
- hostname → environment/service mapping;
- asset-wide Internet-exposed boolean;
- attack path inference;
- Business Impact numeric weights;
- source precedence;
- Formula, Risk, Priority, SLA, or remediation policy.

A later UI may offer suggestions or bulk assistance, but a suggestion must remain visually and semantically distinct from a confirmed association.
