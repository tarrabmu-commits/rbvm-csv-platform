#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sql = " ".join(
    (ROOT / "db/migration/V21__finding_context_association.sql")
    .read_text(encoding="utf-8").split()
).upper()
runtime = " ".join(
    (ROOT / "db/security/runtime-role.sql").read_text(encoding="utf-8").split()
).upper()
migrator = (ROOT / "src/main/java/io/rbvm/postgres/PostgresMigrator.java").read_text(encoding="utf-8")

for needle in (
    "CREATE TABLE RBVM.FINDING_REACHABILITY_SCOPE_LINK_EVENT",
    "CREATE TABLE RBVM.FINDING_BUSINESS_SERVICE_LINK_EVENT",
    "REFERENCES RBVM.EXPOSURE(TENANT_ID, ID)",
    "LINK_STATUS IN ('LINKED', 'UNLINKED')",
    "LINK_METHOD = 'CUSTOMER_CONFIRMED'",
    "TARGET_PORT_KEY INTEGER GENERATED ALWAYS AS (COALESCE(TARGET_PORT, 0)) STORED",
    "TRANSPORT_PROTOCOL IN ('TCP', 'UDP', 'ICMP', 'OTHER', 'UNKNOWN')",
    "ORIGIN_SCOPE IN ( 'INTERNET', 'EXTERNAL_PARTNER', 'INTERNAL_ENTERPRISE', 'LOCAL_SEGMENT', 'OTHER', 'UNKNOWN' )",
    "CREATE VIEW RBVM.CURRENT_FINDING_REACHABILITY_SCOPE_LINK",
    "CREATE VIEW RBVM.ACTIVE_FINDING_REACHABILITY_SCOPE_LINK",
    "CREATE VIEW RBVM.CURRENT_FINDING_BUSINESS_SERVICE_LINK",
    "CREATE VIEW RBVM.ACTIVE_FINDING_BUSINESS_SERVICE_LINK",
    "WHERE LINK_STATUS = 'LINKED'",
):
    if needle not in sql:
        raise AssertionError(f"V21 finding-context migration missing {needle!r}")

for needle in (
    "UNIQUE ( TENANT_ID, FINDING_ID, ORIGIN_SCOPE, ORIGIN_LABEL_NORMALIZED, TRANSPORT_PROTOCOL, TARGET_PORT_KEY, REVISION )",
    "UNIQUE ( TENANT_ID, FINDING_ID, BUSINESS_SERVICE_NORMALIZED, REVISION )",
    "ORDER BY TENANT_ID, FINDING_ID, ORIGIN_SCOPE, ORIGIN_LABEL_NORMALIZED, TRANSPORT_PROTOCOL, TARGET_PORT_KEY, REVISION DESC",
    "ORDER BY TENANT_ID, FINDING_ID, BUSINESS_SERVICE_NORMALIZED, REVISION DESC",
):
    if needle not in sql:
        raise AssertionError(f"V21 finding-context stream invariant missing {needle!r}")

for forbidden in (
    "RISK_SCORE",
    "PRIORITY_TIER",
    "SLA_DAYS",
    "AUTO_LINK",
    "AUTO_MATCH",
    "CVSS_BASE_SCORE",
    "EPSS_PROBABILITY",
    "KNOWN_EXPLOITED",
):
    if forbidden in sql:
        raise AssertionError(f"V21 association persistence must not derive/use {forbidden}")

for relation in (
    "RBVM.FINDING_REACHABILITY_SCOPE_LINK_EVENT",
    "RBVM.FINDING_BUSINESS_SERVICE_LINK_EVENT",
    "RBVM.CURRENT_FINDING_REACHABILITY_SCOPE_LINK",
    "RBVM.ACTIVE_FINDING_REACHABILITY_SCOPE_LINK",
    "RBVM.CURRENT_FINDING_BUSINESS_SERVICE_LINK",
    "RBVM.ACTIVE_FINDING_BUSINESS_SERVICE_LINK",
):
    if relation not in runtime:
        raise AssertionError(f"runtime role is missing V21 association relation {relation}")

for relation in (
    "RBVM.FINDING_REACHABILITY_SCOPE_LINK_EVENT",
    "RBVM.FINDING_BUSINESS_SERVICE_LINK_EVENT",
):
    for operation in ("UPDATE", "DELETE", "TRUNCATE"):
        marker = f"REVOKE UPDATE, DELETE, TRUNCATE ON {relation} FROM RBVM_RUNTIME"
        if marker not in runtime:
            raise AssertionError(f"runtime append-only guard missing for {relation}")
        break

if 'new Migration(21, "V21__finding_context_association.sql")' not in migrator:
    raise AssertionError("PostgresMigrator does not register V21 finding-context association")

if not sql.startswith("BEGIN;") or not sql.endswith("COMMIT;"):
    raise AssertionError("V21 association migration must be transaction-wrapped")

print("V21 finding context association SQL checks: PASS")
