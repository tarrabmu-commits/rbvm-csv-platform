# Increment 14 — CISA KEV API Contract Alignment

This increment aligns the repository-wide OpenAPI and release metadata with the already-implemented CISA KEV runtime API.

The runtime routes already exist; this increment documents and release-aligns them without changing their behavior.

Scope:

- OpenAPI `0.14.0` documentation for `POST /cisa-kev-imports` and `GET /cisa-kev-evidence` under the `/api/v1` server base path.
- `Health.cisaKev` capability schema with independent import/read flags.
- Snapshot-bound KEV import/read schemas preserving LISTED/NOT_LISTED semantics, complete-snapshot provenance, and absence-as-UNKNOWN behavior.
- Release metadata alignment across Gradle, reproducible distribution, verify/release workflows, and README.
- Structural verification that rejects accidental UNKNOWN persistence, loss of snapshot SHA-256 provenance, or missing KEV paths/capabilities.

Validation gates are the existing repository verify suite and CodeQL; the increment is not merge-ready until both succeed on the final head.

No runtime behavior, database schema, source arbitration, EPSS, priority, risk score, or organizational SLA logic is introduced by this increment.
