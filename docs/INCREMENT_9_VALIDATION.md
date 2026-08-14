# Increment 9 — Reproducible and attestable supply chain

Increment 9 hardens how the application is verified, packaged, and released.
Runtime behavior remains unchanged apart from the embedded implementation version.

## Delivered

- Deterministic sorted JAR input inventory and fixed ZIP entry timestamp.
- Fixed manifest producer plus embedded `Implementation-Version`.
- Byte-for-byte double-build verification.
- SHA-256 checksum generated next to every distribution.
- SPDX 2.3 JSON SBOM tied to the JAR digest.
- Distribution inspection that rejects runtime tokens, key registries, runtime data,
  and bundled PostgreSQL JDBC drivers.
- Full 40-character commit pins for every GitHub Action dependency.
- Hash-pinned PyYAML installation in CI.
- Java CodeQL with `security-extended` queries on push, pull request, and schedule.
- CI artifact upload plus build-provenance and SBOM attestations on `main` pushes.
- Tag-only release workflow with version consistency checks and immutable release files.

## Local evidence

`./scripts/verify-reproducible-build.sh` compiles and packages the application
twice from the same controlled toolchain and compares the JAR, checksum, and SBOM.
It also validates the checksum, parses the SBOM as JSON, inspects the fixed manifest,
and scans archive paths for forbidden content.

`./scripts/verify-workflows.py` rejects unpinned actions and action owners outside
the approved `actions/` and `github/` namespaces. The complete verification suite
executes this policy on every change.

## Release verification

For `v0.9.0`, the tag, Gradle version, OpenAPI version, and distribution version
must all equal `0.9.0`. The release job reruns the source and reproducibility suites,
creates both provenance and SPDX attestations, then publishes only:

- `rbvm-csv-platform-0.9.0.jar`
- `rbvm-csv-platform-0.9.0.jar.sha256`
- `rbvm-csv-platform-0.9.0.spdx.json`

Consumers can verify the checksum offline and use GitHub CLI attestation verification
against this repository when network verification is available.

## Boundary

Reproducibility is asserted for the controlled JDK 21 build environment. The JAR
does not bundle pgJDBC; production must independently pin and verify that runtime
dependency. Signing and release attestations originate from GitHub Actions, while
local builds remain checksum-verifiable but are not signed by GitHub.
