# Increment 23 validation — scanner-managed asset link API/UI

Increment 23 must preserve all existing evidence and Decision Input semantics while exposing the existing explicit scanner↔managed-asset link stream operationally.

Validation requirements:

- scanner-asset list is tenant-scoped and UUID cursor paginated;
- never-assessed scanner assets remain distinct from explicit `UNLINKED` decisions;
- current link reads always return a strong ETag, including deterministic revision 0 for never-assessed state;
- every link write requires `If-Match`;
- missing `If-Match` returns 428;
- weak, wildcard, malformed, or list `If-Match` values are rejected;
- stale conflicting writes return 412 and are never merged automatically;
- exact immediately-prior retries may replay without appending a duplicate event;
- `LINKED` requires a tenant-scoped managed asset target;
- `UNLINKED` carries no managed asset target;
- `changedBy` comes only from the authenticated principal;
- `linkMethod` remains server-owned `CUSTOMER_CONFIRMED`;
- unknown/mass-assignment fields are rejected;
- no DELETE or PATCH route exists;
- VIEWER may read, OPERATOR is required to append revisions;
- unavailable link persistence is checked only after authorization so capability state is not leaked pre-auth;
- link history is immutable and newest first;
- UI uses `/api/v1/scanner-assets` and link routes only;
- UI uses `sessionStorage` only for the optional bearer token;
- UI uses DOM/textContent APIs and contains no `innerHTML`, `document.write`, `localStorage`, `DELETE`, or `PATCH` call;
- UI does not infer or auto-select a managed asset;
- UI surfaces 412 for human review with no automatic retry/merge;
- OpenAPI, Gradle/build distribution, verification scripts, workflows, and README agree on release `0.23.0`;
- repository `./scripts/verify.sh`, CodeQL, and reproducible build all pass on the final clean head.

Out of scope: Formula, Risk, Priority, SLA, scanner identity strengthening, automatic matching, relationship confidence scoring, lifecycle-based suppression, and any evidence-source winner.
