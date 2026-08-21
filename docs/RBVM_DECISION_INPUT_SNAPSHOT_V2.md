# RBVM Decision Input Snapshot V2

`RBVM_DECISION_INPUT_SNAPSHOT_V2` evolves the immutable Finding-scoped Decision Input boundary so one evidence dimension can safely reference more than one native evidence store without weakening exact-resolution provenance.

Increment 22 uses this capability for `ASSET_CONTEXT`: existing V13 Asset Context evidence can coexist with customer-managed asset context reached through an explicit V21 scanner-to-managed-asset link.

## Contract

- Contract ID: `RBVM_DECISION_INPUT_SNAPSHOT_V2`
- Semantics: `FINDING_SCOPED_POLICY_BOUND_TYPED_EVIDENCE_REFERENCE_SNAPSHOT`
- Canonical payload: `RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V2`
- Subject: canonical `Finding_ID`
- Methodology: unchanged `RBVM_DECISION_METHODOLOGY_V1`
- Missing evidence: remains absence
- Ambiguity: remains explicit
- Formula/Risk/Priority/SLA: not introduced

V1 snapshots remain valid historical artifacts. Their canonical payload and SHA-256 semantics are not rewritten by V22.

## Why V2 is required

V1 identifies an evidence reference by evidence dimension plus native UUID, SHA-256, semantic source, and observation time. That is sufficient while each dimension has one native evidence store.

After the managed-asset registry and explicit scanner-to-managed-asset link exist, `ASSET_CONTEXT` can refer to either:

1. V13 `rbvm.asset_context_evidence`; or
2. V18 `rbvm.managed_asset_revision` reached through an explicit V21 link event.

A V13 `Context_Source` is customer/source text and is not a native-table discriminator. Therefore V22 must not dispatch by source text or search multiple tables until one UUID happens to match.

V2 adds `NativeEvidenceKind`; exact native identity is:

```text
nativeEvidenceKind + evidenceId
```

## Native evidence kinds

V2 recognizes these typed native stores:

- `APPLICABILITY_ASSESSMENT`
- `CVSS_V31_BASE_EVIDENCE`
- `CISA_KEV_EVIDENCE`
- `EPSS_EVIDENCE`
- `ASSET_CONTEXT_EVIDENCE`
- `MANAGED_ASSET_REVISION`
- `NETWORK_REACHABILITY_EVIDENCE`
- `BUSINESS_IMPACT_EVIDENCE`

The type is provenance and dereference identity. It is not source precedence and carries no risk weight.

## Managed-asset binding provenance

A `MANAGED_ASSET_REVISION` reference is invalid unless it also carries one exact immutable binding reference:

- binding kind `SCANNER_MANAGED_ASSET_LINK_EVENT`;
- V21 link-event UUID;
- link-event evidence SHA-256;
- link method/source (`CUSTOMER_CONFIRMED` in V21);
- link-event `recorded_at`.

The resolver verifies both immutable rows. It also verifies that the link is `LINKED`, targets the managed asset owning the referenced revision, and originates from the scanner asset belonging to the snapshot Finding.

No hostname, IP address, OS, product, vulnerability, CVSS, KEV, EPSS, or scanner-severity inference is accepted as a binding.

## As-of selection

For schema version 20 and later, the builder evaluates managed context at the explicit snapshot `evaluatedAt`:

1. V13 Asset Context history remains eligible exactly as before.
2. Read V21 link-event history for the Finding scanner asset with `recorded_at <= evaluatedAt`.
3. Choose the highest link revision in that as-of history.
4. No link history contributes no managed context.
5. A latest `UNLINKED` decision contributes no managed context.
6. A latest `LINKED` decision identifies one managed asset and becomes the binding reference.
7. Read that managed asset's revision history with `recorded_at <= evaluatedAt` and choose the highest revision.
8. Add that exact revision as a typed `MANAGED_ASSET_REVISION` candidate.

The builder does not use `current_*` or `active_*` convenience views for this historical decision boundary.

Managed-asset lifecycle and scanner-link state remain separate contracts. A `RETIRED` managed-asset revision is not silently discarded by V22; any later lifecycle eligibility rule must be separately versioned and explicit.

## Coexistence with V13 Asset Context

V13 and managed-asset context share the existing `ASSET_CONTEXT` evidence dimension and the same Finding asset sub-grain. V22 does not introduce a managed-asset-wins rule.

`RBVM_DECISION_METHODOLOGY_V1` continues to apply its existing source policy:

- `ALL_SOURCES`; or
- `EXPLICIT_ALLOWLIST`.

The allowlist remains a semantic-source filter, not a precedence list.

Latest-per-source selection is isolated by both semantic source and native evidence kind. Therefore a V13 source named `CUSTOMER_ASSET_REGISTRY` cannot be silently collapsed with the actual managed-asset registry stream. If both remain admissible for the asset sub-grain, the dimension remains `AMBIGUOUS` as required by the methodology contract.

## Persistence compatibility

PostgreSQL migration V20 adds typed-reference and optional binding columns to `rbvm.decision_input_evidence_reference`, backfills historical V1 rows with their dimension-derived native kind, and changes reference uniqueness to include native evidence kind.

The snapshot table accepts both V1 and V2 contract/semantics/payload-format tuples. New V2 snapshots require schema version 20. Older schema 17–19 runtimes continue to build and resolve V1 snapshots only.

## Standards classification

The V22 typed native-reference and explicit binding-provenance mechanics are **RBVM_POLICY**: they are platform rules needed to preserve exact provenance across RBVM's own evidence stores.

The underlying customer/business context vocabulary retains its previously documented NIST/FIPS traceability. V22 does not claim that NIST, FIPS, FIRST, CISA, or OWASP defines this exact snapshot format, native-kind taxonomy, or scanner-to-managed-asset binding model.

## Deliberate non-goals

V22 adds no:

- risk formula or score;
- priority tier;
- remediation/treatment SLA;
- source winner or precedence order;
- automatic scanner-to-managed-asset matching;
- lifecycle-based context suppression;
- Case roll-up;
- monetary-loss model;
- attack-path score.

The result remains an immutable, explainable input boundary suitable for a later separately versioned Formula contract.
