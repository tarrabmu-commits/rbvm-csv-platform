# CISA BOD 26-04 Priority Input Snapshot V1

Contract ID: `CISA_BOD_26_04_PRIORITY_INPUT_SNAPSHOT_V1`

Schema version: `1`

Method binding:

- `CISA_BOD_26_04_REMEDIATION_PRIORITY_METHOD_V1`
- SHA-256 `64066ae687fd98c6db48fa224316446dc579737ff6c16321f155de69c5f0e9ff`

## Purpose

This artifact is the immutable boundary between evidence acquisition/customer context and the later CISA BOD 26-04 decision engine.

It does **not** calculate an outcome.

Each finding row binds exactly four decision points:

1. `InKEV` — `cisa:KEV:1.0.0`
2. `PubliclyExposed` — `cisa:PE:1.0.0`
3. `Automatable` — `ssvc:A:2.0.0`
4. `TechnicalImpact` — `ssvc:TI:1.0.0`

The snapshot preserves raw values, normalized canonical values, evidence status, blockers, and exact source provenance. The entire artifact receives its own canonical SHA-256.

## Source artifacts

The builder consumes:

- one immutable `CSV_RUN_EVIDENCE_ANALYSIS_V3` CSV;
- its analysis summary with exact `RBVM_CUSTOMER_ASSET_BUNDLE_V4` SHA-256;
- one `CISA_KEV_VALIDATED_SNAPSHOT` produced by the canonical CISA KEV validator.

The validated KEV snapshot is mandatory because a negative BOD `InKEV=N` decision is only valid when absence is established against a complete catalog.

The builder rejects KEV snapshots unless:

```text
complete = true
declaredCount > 0
declaredCount = parsedCount
parsedCount = vulnerabilities.length
unique valid CVE IDs
valid source SHA-256
```

Therefore:

```text
blank/missing KEV evidence != N
unvalidated public-intel KEV absence != N
absence from validated complete CISA snapshot = N
presence in validated complete CISA snapshot = Y
```

The contextual analysis CSV's `KEV_Listed` column is not used to manufacture a negative membership result. This avoids converting an incomplete or differently timed convenience view into canonical BOD evidence.

## Publicly Exposed provenance

`PubliclyExposed` is read from the V4-derived analysis column `Publicly_Exposed` and is bound to:

- `RBVM_CUSTOMER_ASSET_BUNDLE_V4`;
- schema version `4`;
- exact customer-bundle SHA-256;
- source `CUSTOMER_DECLARED_CISA_PUBLICLY_EXPOSED`.

Legacy `Internet_Facing` is not read by the BOD snapshot builder and is not an input.

## CISA SSVC provenance

`Automatable` and `TechnicalImpact` are resolved from the CISA Vulnrichment columns:

- `CISA_Automatable`;
- `CISA_Technical_Impact`.

For a PRESENT SSVC value, exact CVE Services response provenance is mandatory:

- `CVE_Services_Response_SHA256`;
- `CISA_SSVC_Version`;
- `CISA_SSVC_Timestamp`;
- `Public_Intel_Snapshot_SHA256`;
- `Intel_Observed_At`.

A syntactically valid SSVC value without a valid response SHA becomes `INVALID`, not PRESENT.

Generic `CISA_Exploitation` remains outside this contract because BOD 26-04 uses `InKEV` as its exploitation decision point.

## Per-input states

Each decision point has:

```text
semanticId
status = PRESENT | MISSING | INVALID
value  = canonical value or null
raw    = source value
blocker
provenance
```

Canonical values are:

- In KEV: `Y / N`
- Publicly Exposed: `Y / N`
- Automatable: `Y / N`
- Technical Impact: `P / T`

Explicit `UNKNOWN`, `MISSING`, `INCOMPLETE`, or blank source values remain `MISSING`.

## Row status

A row is:

```text
COMPLETE
```

only when all four inputs are `PRESENT`.

Otherwise it is:

```text
INCOMPLETE
```

with exact blockers. The snapshot never chooses a BOD table row for an incomplete finding.

## Finding scope

The snapshot is row-preserving and records only identity/scope fields needed to correlate the decision later:

- row number;
- CVE ID;
- asset key/name when present;
- vulnerable component when present;
- canonical SHA-256 of the complete source analysis row.

The row SHA commits to the immutable source row but does not make unrelated fields BOD calculation inputs.

## Explicit non-inputs

The snapshot does not copy or normalize the following as BOD decision dimensions:

- CVSS-B/CVSS-BT/CVSS-BE/CVSS-BTE;
- EPSS probability/percentile;
- Asset Criticality;
- Business/Mission Impact;
- legacy Internet Facing;
- Organizational Risk / Formula outputs;
- presentation `LOW/MEDIUM/HIGH/CRITICAL` tiers.

Those values may remain available in their own evidence/analysis artifacts but cannot change the later CISA BOD outcome.

## Reproducibility

The snapshot records SHA-256 identities for:

- analysis CSV;
- analysis summary file;
- customer bundle;
- validated KEV snapshot file;
- original CISA KEV source bytes;
- per-row source analysis content;
- public-intel snapshot and CISA-ADP response for SSVC.

The snapshot itself is canonicalized with sorted JSON keys and compact separators, then assigned `snapshotSha256` over the object before that field is added.

A later decision engine must consume this snapshot as-is. It must not re-query current evidence or silently replace any decision point.
