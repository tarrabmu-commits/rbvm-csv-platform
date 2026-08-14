# Increment 8 — API abuse resistance and key lifecycle

Increment 8 tightens the internal bearer-key boundary delivered by Increment 7.
It remains an internal-service control and is not a replacement for OIDC/MFA at
a trusted TLS ingress.

## Delivered

- Optional ISO-8601 expiration on API-key registry entries.
- Startup rejection for duplicate digests and registries with no unexpired key.
- POSIX startup rejection when the registry grants any group/other permission.
- Case-insensitive Bearer scheme handling while retaining exact opaque token bytes.
- Separate fixed-window limits for authenticated actors and failed-auth sources.
- Bounded in-memory limiter state, automatic stale-window removal, `429`, and
  `Retry-After` responses.
- Metrics for authentication failures, authorization denials, and rate limiting.
- Public readiness reduced to `status` and `checkedAt`; detailed health now requires
  `VIEWER` or a stronger role.
- Expiring-key creation and exact-token revocation tools.
- Deployment environment defaults for both rate limits.

Registry entries are backward compatible:

```text
sha256=actor-id|ROLE
sha256=actor-id|ROLE|2026-12-31T23:59:59Z
```

Multiple active keys may intentionally share an actor during rotation. Duplicate
digests are rejected. An expired key never authenticates, and startup fails when
every configured key is expired.

## Automated evidence

The security suite verifies active/expired keys, lowercase Bearer parsing,
duplicate rejection, all-expired rejection, per-actor isolation, failed-auth
isolation, `429`, and exact `Retry-After` behavior. The HTTP suite verifies that
public readiness contains no observation counts, detailed health is protected,
and existing Viewer/Operator authorization and authenticated audit attribution
continue to work.

The complete suite is run by `./scripts/verify.sh` and the live validation is run
against the TLS PostgreSQL runtime before publication.

## Remaining boundary

- Fixed-window limits protect ordinary abuse and credential guessing but are not
  a distributed denial-of-service control. Enforce network and ingress limits too.
- Restart is required after registry rotation or revocation so there is no ambiguous
  partially-written hot-reload state.
- OIDC, MFA, centralized revocation, and user lifecycle remain ingress/identity
  platform responsibilities.
