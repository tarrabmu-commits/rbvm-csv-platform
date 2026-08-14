# Increment 12 — intelligence freshness and scheduling

Increment 12 makes enrichment operational without making ingestion depend on
live third-party services.

## Behavior

- Catalog summaries expose enriched, un-enriched, stale, and CISA KEV counts,
  plus oldest/newest observation times and the complete priority distribution.
- Intelligence is stale when its current `Intel_Observed_At` is more than 168
  hours old. Staleness is an explicit signal; it does not erase evidence or
  silently change the priority tier.
- `scheduled-intelligence-refresh.sh` serializes runs with `flock`, creates
  immutable timestamped snapshots, checksums them, updates atomic `latest`
  symlinks, and safely retains a bounded history.
- NVD and EPSS cache filenames include a SHA-256-derived identity for the exact
  sorted CVE batch. Offline mode therefore fails closed when the requested CVE
  set has no matching cache.
- The scheduler does not auto-import its output. Finding lifecycle remains based
  on a current, explicitly uploaded Wazuh V2 export rather than a stale scheduled
  input.

The official upstream sources remain:

- https://nvd.nist.gov/developers/vulnerabilities
- https://api.first.org/epss/
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Validation gates

- Java domain, HTTP, PostgreSQL projection, API, web, workflow, and shell checks.
- Deterministic offline enrichment with fixed observation time and JSON report.
- Cache-key mismatch rejection for a different CVE set.
- Scheduled wrapper lock/output/checksum/latest-link integration test.
- Reproducible 0.12.0 JAR, checksum, and SPDX SBOM.
- Live PostgreSQL summary, systemd timer, and official-source refresh smoke test.

## Completed evidence

- `./scripts/verify.sh` and `./scripts/verify-release-version.sh v0.12.0` pass.
- Two clean builds produce JAR SHA-256
  `ae0b7aa04f14efca0d2bf5ffd6ff3ee203549957c22e7152eaf638584a98a58b`.
- The live catalog reports 2,267 tenant-visible vulnerabilities: one current
  enriched CISA KEV vulnerability and 2,266 explicitly un-enriched, with zero
  stale current intelligence records.
- The official-source scheduled run completed online, its checksum verifies,
  and `rbvm-intelligence-refresh.timer` is enabled for daily persistent runs.
- Live PostgreSQL remains at schema 7 with zero reconciliation issues, TLS and
  append-only audit privileges intact.
- PostgreSQL, the application, the verified-backup timer, and the intelligence
  refresh timer are all active after the final restart.
