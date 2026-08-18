# RBVM Readiness Foundation — Wazuh Evidence Boundary

This foundation step defines what the current Wazuh source can and cannot prove before any RBVM methodology, scoring model, threat priority, or remediation decision is applied.

## Current real Wazuh export

The currently observed Wazuh CSV shape is `WAZUH_CSV_V1`:

```text
Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At
```

It provides useful vulnerability observations, but it does not prove:

- a stable Wazuh Agent ID;
- package version;
- package architecture;
- explicit finding lifecycle (`ACTIVE` / `RESOLVED`).

These facts must remain explicitly unavailable rather than being inferred from unrelated fields.

## Evidence capability model

The platform exposes source capabilities as facts, not as a confidence score.

| Capability | WAZUH_CSV_V1 | WAZUH_CSV_V2 |
|---|---:|---:|
| Stable asset ID | No | Yes |
| Package version | No | Yes |
| Package architecture | No | Yes |
| Explicit finding lifecycle | No | Yes |
| RBVM finding identity ready | No | Yes |
| RBVM lifecycle ready | No | Yes |

`WAZUH_CSV_V1` remains valid evidence. The capability boundary does **not** reject it and does not weaken the existing ingestion path. It prevents downstream RBVM stages from silently treating unavailable evidence as known facts.

## Canonical direction

The intended pipeline is:

```text
Raw Wazuh evidence
        |
        v
Validation + immutable Observation
        |
        v
Source evidence capability boundary
        |
        v
Canonical finding identity
        |
        v
Canonical finding state
        |
        v
Applicability
        |
        v
Technical severity
        |
        v
RBVM-ready evidence
```

The canonical finding layer preserves provenance and distinguishes:

1. facts directly observed in Wazuh;
2. facts obtained from an additional trusted Wazuh source such as the Indexer/API;
3. unavailable facts;
4. later external intelligence such as CVSS, KEV, or EPSS.

No RBVM risk equation or priority policy belongs in this foundation layer.

## Canonical finding identity

A CSV row is an immutable **Observation**. A logical finding may have many observations.

The platform derives a `CanonicalFindingIdentity` from each observation.

For `WAZUH_CSV_V1` the grouping identity is deliberately source-limited:

```text
Source Profile
+ normalized Agent name
+ CVE
+ normalized Affected_Product
```

Its identity strength is `SOURCE_LIMITED` because the source does not provide stable `Agent_ID`, package version, or architecture.

For `WAZUH_CSV_V2` the grouping identity is stronger:

```text
Source Profile
+ stable Agent_ID
+ CVE
+ normalized Product + Package_Version + Package_Architecture
```

Its identity strength is `SOURCE_STABLE`.

Two observations can therefore share one canonical finding identity while keeping distinct observation fingerprints and timestamps. Changing a V2 package version produces a different canonical finding identity.

This identity is only a grouping key. It does **not** assert that the vulnerability is applicable, exploitable, remediated, or high risk.

## Canonical finding state

`CanonicalFindingState` aggregates distinct immutable observations that share one `CanonicalFindingIdentity`.

It records only evidence-derived state:

- `firstObservedAt`: earliest `Detected_At` seen for the finding;
- `lastObservedAt`: latest `Detected_At` seen for the finding;
- `observationCount`: count of distinct observation fingerprints;
- `stateEvidenceAt`: timestamp of the evidence currently determining source state;
- `sourceState`;
- whether lifecycle evidence is explicit in the source contract.

### V1 lifecycle semantics

`WAZUH_CSV_V1` cannot prove remediation. Its canonical state is therefore:

```text
sourceState = OBSERVED_ONLY
explicitLifecycle = false
```

A later file that does not contain the finding does not change this state. Absence is not a lifecycle event.

### V2 lifecycle semantics

`WAZUH_CSV_V2` carries explicit `ACTIVE` / `RESOLVED` evidence. The canonical state uses the latest source evidence timestamp (`Detected_At` for ACTIVE, `Resolved_At` for RESOLVED).

```text
ACTIVE evidence   -> ACTIVE
RESOLVED evidence -> RESOLVED
newer ACTIVE      -> ACTIVE again (reopened at source)
```

If ACTIVE and RESOLVED evidence conflict at the exact same evidence timestamp, ACTIVE wins conservatively. This prevents a same-time conflict from creating a false closure.

Duplicate observation fingerprints are idempotent and do not increase `observationCount`.

The state layer still does **not** determine applicability, exploitability, CVSS severity, remediation priority, SLA, or organizational risk.

## Current implementation status

Completed:

- source evidence capability boundary;
- canonical finding identity model;
- V1 repeated-observation grouping semantics;
- V2 stable-agent grouping semantics;
- V2 package-version separation semantics;
- canonical finding state aggregation;
- V1 `OBSERVED_ONLY` semantics without inferred remediation;
- V2 explicit resolution and reopen semantics;
- conservative same-timestamp ACTIVE/RESOLVED conflict handling;
- idempotent observation counting;
- self-tests for the above behavior.

## Next implementation step

Add a separate **applicability evidence** model. Applicability must answer whether the detected CVE applies to the actual component/deployment using explicit evidence and an `APPLICABLE / NOT_APPLICABLE / UNKNOWN` state. It must remain separate from CVSS severity and from any future RBVM decision model.
