# Pre-V24 Hardening

This corrective pass does not define or calculate Risk, Priority, Treatment, or SLA. It closes
operational proof and UI/documentation debt before `RBVM_FORMULA_V1`.

## Verification boundary

- Standard dependency-free verification and CodeQL remain required.
- A dedicated PostgreSQL integration workflow migrates a disposable database through V20.
- The live test uses the restricted `rbvm_runtime` role for V18 managed assets, V19 explicit
  scanner↔managed-asset links, and V16/V17/V20 Decision Methodology/Input operations.
- It proves create/revise, LINK/replay/UNLINK/history, V2 build/persist/resolve, historical as-of
  behavior, and denied UPDATE/DELETE against append-only tables.
- PostgreSQL CI uses a digest-pinned PostgreSQL 16.14 image and pgJDBC 42.7.13 with a pinned
  SHA-256. TLS is intentionally disabled only on the loopback disposable CI service; production
  TLS remains a deployment control documented separately.

## UI corrections

Managed Asset creation no longer defaults Environment, Business Criticality, or Classification
Method to meaningful customer values. The operator must choose each explicitly. Table captions
remain available to assistive technology, guide revisions use integer stepping, and the revision
flow avoids stacking one modal dialog on top of another.

## Formula boundary

No formula, numeric criticality multiplier, source precedence, priority tier, or SLA rule is added
by this pass. V24 remains the Formula contract increment after these gates are green.

The Gradle Java toolchain now targets Java 17, matching the compiler `--release 17` and documented runtime floor.
