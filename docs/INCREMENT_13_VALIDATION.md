# Increment 13 Validation — API Contract Alignment

Increment 13 aligns the published API/release contract with the already-implemented Applicability and independent CVSS v3.1 Base operator workflows.

## Scope

This increment does not add RBVM scoring or new evidence semantics. It publishes and verifies the runtime contract that already exists:

```text
Applicability
  GET  /api/v1/applicability-findings.csv
  POST /api/v1/applicability-imports

CVSS v3.1 Base
  GET  /api/v1/cvss-v31-evidence
  POST /api/v1/cvss-v31-imports
  GET  /cvss
```

The OpenAPI document is bumped to `0.13.0` and the Gradle, reproducible JAR, release workflow, README, and release-version checks are aligned to the same semantic version.

## Contract invariants

The automated OpenAPI verifier requires:

- OpenAPI `3.1.1`;
- API version `0.13.0`;
- unique `operationId` values;
- valid local `$ref` targets;
- bearer authentication as the default API security policy;
- Applicability import/export paths;
- CVSS v3.1 import/current-evidence paths;
- `Health.cvssV31` capability reporting;
- CVSS capability fields `importEnabled` and `evidenceReadEnabled`;
- `CvssV31ImportResult` with inserted/replayed/parser/persistence quarantine accounting;
- exact `CVSS_V31_CSV_V1` and `CVE_SCOPED_CVSS_V31_BASE_EVIDENCE` semantics;
- current CVSS read semantics `CURRENT_PER_SOURCE_CVSS_V31_BASE_EVIDENCE`;
- exact CVSS version `3.1` and Base score range `0..10`;
- applicability fields surfaced on PostgreSQL exposure/finding reads.

## CVSS boundary represented by the API

The API publishes CVSS as technical-severity evidence only:

```text
CVE
 + CVSS version 3.1
 + Base score
 + Base vector
 + CVSS source
 + CVSS observed-at
```

The current-evidence response remains **per source**. The OpenAPI contract deliberately does not define:

```text
CVSS source winner
CVSS -> priority conversion
risk score
SLA
EPSS combination
KEV combination
asset criticality
business impact
```

The older combined `VulnerabilityIntelligence` API object remains documented as compatibility behavior so the release contract does not silently pretend that legacy fields disappeared.

## Release-version invariant

A valid `v0.13.0` release must agree across:

```text
build.gradle.kts                  0.13.0-SNAPSHOT
api/openapi.yaml                  0.13.0
scripts/build-distribution.sh     VERSION=0.13.0
release artifact                  rbvm-csv-platform-0.13.0.jar
SBOM                              rbvm-csv-platform-0.13.0.spdx.json
```

`scripts/verify-release-version.sh` rejects a release tag when those sources disagree.

## Automated validation

The repository verification path is:

```bash
./scripts/verify.sh
./scripts/verify-reproducible-build.sh
./scripts/verify-release-version.sh v0.13.0
```

`verify.sh` covers Java contract/domain/HTTP tests, OpenAPI structure, SQL, web resources, workflow hardening, enrichment checks, and shell syntax. The reproducible-build test builds twice with a fixed source date, compares JAR/checksum/SBOM byte-for-byte, verifies the SHA-256 file, validates SPDX JSON, checks manifest version `0.13.0`, and rejects forbidden runtime secrets/data/JDBC drivers from the distribution.

GitHub pull-request validation must also complete the repository `verify` and `codeql` workflows before merge.

## Acceptance condition

Increment 13 is acceptable when all of the following are true:

```text
OpenAPI structural checks: PASS
PlatformSelfTest: PASS
reproducible_build=PASS
release_version=PASS version=0.13.0
GitHub verify workflow: success
GitHub CodeQL workflow: success
```

The next stage after this release-contract alignment is not a scoring formula. It is an official-source collector that feeds the existing `CVSS_V31_CSV_V1` validation/import boundary while preserving CVSS-specific provenance and observation time.
