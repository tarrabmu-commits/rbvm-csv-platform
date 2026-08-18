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

The platform now exposes source capabilities as facts, not as a confidence score.

| Capability | WAZUH_CSV_V1 | WAZUH_CSV_V2 |
|---|---:|---:|
| Stable asset ID | No | Yes |
| Package version | No | Yes |
| Package architecture | No | Yes |
| Explicit finding lifecycle | No | Yes |
| RBVM finding identity ready | No | Yes |
| RBVM lifecycle ready | No | Yes |

`WAZUH_CSV_V1` remains valid evidence. The new capability boundary does **not** reject it and does not weaken the existing ingestion path. It prevents downstream RBVM stages from silently treating unavailable evidence as known facts.

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
Canonical finding construction
        |
        v
Applicability / lifecycle / technical severity
        |
        v
RBVM-ready evidence
```

The canonical finding layer must preserve provenance and distinguish:

1. facts directly observed in Wazuh;
2. facts obtained from an additional trusted Wazuh source such as the Indexer/API;
3. unavailable facts;
4. later external intelligence such as CVSS, KEV, or EPSS.

No RBVM risk equation or priority policy belongs in this foundation layer.

## Next implementation step

The next change is to make canonical finding construction consume these capabilities explicitly, so a V1 observation cannot accidentally be treated as if it contained stable asset identity, package coordinates, or remediation lifecycle evidence.
