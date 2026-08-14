# Increment 7 — Security and production hardening

Validated locally on 2026-08-14. This increment adds an explicit HTTP security
boundary and operational probes; it does not claim internet-facing production
readiness without a TLS ingress and an external identity provider.

## Delivered

- File-backed opaque bearer keys with SHA-256-only server storage.
- Constant-time digest comparison via `MessageDigest.isEqual`.
- Deny-by-default authorization on data routes.
- `VIEWER`, `OPERATOR`, and `ADMIN` role hierarchy.
- Authenticated `actorId` and `API_KEY_SHA256` assurance on workflow events.
- Public `/api/v1/live` and `/api/v1/ready` probes.
- Authenticated Prometheus text endpoint at `/api/v1/metrics`.
- Session-scoped token handling in the Arabic web UI.
- Systemd service restrictions, mode-600 local secret files, and a key creation tool.
- GitHub Actions verification/build workflow with read-only repository permission.
- Automated PostgreSQL restart/recovery validation.
- Daily systemd backup timer with SHA-256 checksum, restore verification, and bounded retention.

## Verification evidence

`./scripts/verify.sh` passes contract, domain, HTTP, projection, migration,
OpenAPI, SQL, web, and shell structural checks. The HTTP suite additionally
proves:

- missing or invalid bearer token returns `401` and a Bearer challenge;
- invalid token material is absent from the response;
- a Viewer can read but receives `403` for an upload;
- an Operator can import and record a case action;
- the audit event contains the authenticated actor and assurance.

The live PostgreSQL verification after authentication reports:

```text
live_postgres=PASS schema=5 counts=10001|5|2265|602|9090|7521|226 reconciliation=0 ssl=t audit_privileges=t|f|f auth=401
postgres_restart_recovery=PASS recovery_seconds=1
```

The second live verification after the restart returned the same row counts,
zero reconciliation drift, TLS enabled, append-only audit privileges, and a
healthy service.

The first scheduled run restored `10001|7521|2` observation/case/audit rows into
a temporary validation database and exited successfully. The timer is enabled
with a randomized daily trigger and keeps 14 verified backup generations by default.

## Threat boundary and remaining production work

- The built-in bearer-key scheme is intended for a controlled internal service.
  Internet or shared-network exposure requires TLS at a trusted ingress.
- The raw token must be distributed through an approved secret channel and
  rotated by adding a replacement digest, deploying it, then removing the old digest.
- API keys are not user sessions and do not provide MFA, SSO lifecycle, device
  posture, or per-request proof of possession. Use OIDC at the ingress for those needs.
- Readiness exposes dependency detail for local operations. Restrict probe routes
  with network policy when deployed beyond loopback.
- PostgreSQL restart recovery validates single-node reconnect behavior. Actual HA,
  replication, failover fencing, RPO, and RTO require the target infrastructure.
