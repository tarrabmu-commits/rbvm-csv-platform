# RBVM Dashboard V3

Contract: `RBVM_DASHBOARD_V3`

## Purpose

Dashboard V3 adapts the strongest operational ideas from the earlier VA dashboard into the current RBVM platform without carrying forward semantics that are no longer defensible.

The earlier VA dashboard included operational KPI cards, severity distributions, vulnerable/exploitable asset views, age distributions, trend charts, remediation metrics, and SLA charts. Dashboard V3 keeps the useful presentation model while binding every visible metric to evidence already available from the canonical RBVM APIs.

## Included now

The Overview dashboard includes:

- Current findings;
- Unique CVEs;
- Exposure instances;
- affected assets;
- CISA KEV known-exploited coverage;
- customer-managed Mission Critical asset count;
- current technical-severity distribution;
- KEV-listed vs not-listed/not-established signal view;
- most affected observed assets;
- Critical/High + KEV concentration by asset;
- current finding age distribution;
- customer-declared Asset Criticality distribution;
- CVSS, EPSS, and KEV evidence coverage;
- explicit historical-trend readiness messaging.

## Semantic translations from the VA dashboard

### Exploitable

The old implementation could classify exploitability from a local `exploitable_cves.txt` list. RBVM does not reuse that shortcut.

Dashboard V3 uses **CISA KEV known-exploited evidence** where available. A finding that is not KEV-listed is described as `Not listed / not established`; it is never labeled non-exploitable or safe.

### Critical assets

The earlier implementation used a local critical-agent list. RBVM uses customer-managed **Asset Criticality** where available. Vulnerability severity is never used to infer asset criticality.

### Trend and remediation

The VA tool calculated New / Remediated / Total from stored periodic snapshots. The current canonical case API is current-state oriented and does not expose the historical aggregate series required to reproduce that chart without survivor bias.

Therefore Dashboard V3 explicitly marks the trend as requiring a historical aggregation API. It does not reconstruct New / Remediated / Total from current-state rows.

### SLA

The earlier `va.py` contained local SLA values such as Critical=3 days and High=30 days. Those values are not an approved RBVM treatment/SLA policy.

Dashboard V3 does not display SLA compliance until an explicit, versioned RBVM treatment/SLA contract exists.

## Risk boundary

Dashboard V3 is presentation and current-state analytics only.

It does not calculate Organizational Risk, does not multiply CVSS × EPSS, does not introduce weights or thresholds, and does not convert KEV, technical severity, Asset Criticality, or finding age into a hidden score.

## Data sources

The module consumes existing same-origin APIs:

- `/api/v1/catalog/summary`
- `/api/v1/cases`
- `/api/v1/managed-assets`

No new source-of-truth store is created by the dashboard.
