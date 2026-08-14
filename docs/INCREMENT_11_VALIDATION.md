# Increment 11 — vulnerability intelligence

Increment 11 adds optional provenance-bound CVSS, EPSS, and CISA KEV evidence to
`WAZUH_CSV_V2`. Base ingestion remains offline-capable: enrichment is performed
before upload and the enriched CSV is retained as raw evidence.

## Priority policy

The tier is a transparent local policy, not a claim that CVSS equals risk:

- `IMMEDIATE`: listed in CISA KEV;
- `URGENT`: EPSS >= 0.10 or CVSS >= 9.0;
- `HIGH`: EPSS >= 0.01 or CVSS >= 7.0;
- `STANDARD`: enriched evidence below those thresholds;
- `UNENRICHED`: no accepted intelligence evidence.

Every intelligence-bearing row requires `Intel_Observed_At` and one or more HTTPS
source references. CVSS fields and EPSS fields are atomic groups, numeric ranges
are enforced, and KEV dates cannot accompany `Known_Exploited=false`.

The helper `scripts/enrich-wazuh-v2.py` uses the NVD CVE 2.0 API, FIRST EPSS API,
and CISA KEV JSON feed. Responses are cached atomically; `--offline` refuses
network access and requires a complete cache. `NVD_API_KEY` is read only from the
environment and is never placed in URLs or output.

Official source documentation:

- https://nvd.nist.gov/developers/vulnerabilities
- https://api.first.org/epss/
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Validation evidence

- `./scripts/verify.sh`: all Java, HTTP, PostgreSQL projection, OpenAPI, SQL,
  web, workflow, and shell structural checks pass.
- `./scripts/verify-reproducible-build.sh`: two clean builds produce SHA-256
  `a7f108d5f7c5bec57e636cb47d0a17361640e89c1e30487197bd0ce27b5bc597`.
- The enrichment helper completed both an online official-source run and a
  cache-only `--offline` replay for the same retained V2 input.
- V7 is installed in the live PostgreSQL instance with zero projection
  reconciliation issues.
- A retained live import for `CVE-2026-43434` materialized CVSS 9.8, EPSS 0.55,
  and CISA KEV evidence as priority `IMMEDIATE` through the PostgreSQL-backed
  API. The combined `priority=IMMEDIATE`, `knownExploited=true`, and CVE query
  returned that case after the final service restart.
- `./scripts/verify-live-postgres.sh`: schema 7, TLS enabled, append-only audit
  privileges intact, zero reconciliation issues, authentication enforced, and
  PostgreSQL, application, and backup timer all active.
