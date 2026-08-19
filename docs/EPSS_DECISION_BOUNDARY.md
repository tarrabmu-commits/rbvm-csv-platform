# EPSS Decision Boundary

The canonical EPSS path preserves source evidence and stops before organizational decision logic.

```text
EPSS probability / percentile
        ↓
validated CVE-scoped evidence
        ↓
future persistence and freshness
        ↓
RBVM decision layer (later, separate)
```

The EPSS contract must not implement threshold-to-priority mapping, CVSS/KEV formulas,
asset criticality weighting, organizational SLA, or business-impact decisions.

A missing score is absence of usable EPSS evidence, not `0`, `LOW`, or `SAFE`.
