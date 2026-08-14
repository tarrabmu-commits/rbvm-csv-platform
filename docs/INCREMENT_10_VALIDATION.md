# Increment 10 validation

Increment 10 adds the opt-in `WAZUH_CSV_V2` explicit finding lifecycle while
preserving V1 as the default.

Validated invariants:

- strict V2 headers, stable Agent ID, package version and architecture;
- `ACTIVE` forbids `Resolved_At`; `RESOLVED` requires a timestamp not before detection;
- absence-only imports leave active cases open;
- explicit resolution changes a fully resolved case to `SOURCE_RESOLVED`;
- newer active evidence reopens it; active wins equal-time lifecycle conflicts;
- manual risk decisions are not overwritten by source lifecycle ingestion;
- import metadata persists the contract and rebuild uses the same contract;
- PostgreSQL migration V6 stores immutable lifecycle evidence and package identity;
- V1 contract and reference regression remain green.

Run `./scripts/verify.sh`, `./scripts/verify-reproducible-build.sh`, and the live
PostgreSQL verification scripts before release.

## Local validation evidence (2026-08-14)

- source, domain, HTTP, JDBC, OpenAPI, SQL, web, workflow and shell checks: PASS;
- reproducible JAR: `rbvm-csv-platform-0.10.0.jar`;
- SHA-256: `b8b3951f7819537a762bf667b37b282c5d2a334ee9d5150814c1671586259e16`;
- live migration: schema `6`, projection `UP`, reconciliation issues `0`;
- authenticated API smoke test on source profile `increment10-live-v2`:
  `ACTIVE -> SOURCE_RESOLVED -> OPEN` passed.

The live smoke-test profile is intentionally retained as immutable test evidence;
it is isolated from the V1 reference profile and uses CVE-2026-42424.
