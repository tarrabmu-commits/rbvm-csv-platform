# EPSS Stage

Current independent EPSS path:

```text
FIRST official daily bulk feed
        ↓
FIRST_EPSS_VALIDATED_SNAPSHOT        ✅
        ↓
EPSS_CSV_V1                          ✅
        ↓
PostgreSQL history/current            ⬜
        ↓
Transactional importer                ⬜
        ↓
API / operator UI                     ⬜
        ↓
Authenticated safe handoff            ⬜
        ↓
Scheduled refresh                     ⬜
```

EPSS remains CVE-scoped exploitation-probability evidence only. No threshold,
priority, risk score, SLA, CVSS/KEV formula, asset criticality, or business-impact
policy is introduced by the source-adapter or CSV-contract stages.
