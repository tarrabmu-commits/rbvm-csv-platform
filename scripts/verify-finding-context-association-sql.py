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

# Compact forms deliberately ignore whitespace-only SQL formatting differences while retaining
# punctuation, identifiers, literals, and ordering as semantic assertions.
compact_sql = "".join(sql.split())
compact_runtime = "".join(runtime.split())

for needle in (
    "CREATE TABLE RBVM.FINDING_REACHABILITY_SCOPE_LINK_EVENT",
    "CREATE TABLE RBVM.FINDING_BUSINESS_SERVICE_LINK_EVENT",
    "CREATE VIEW RBVM.CURRENT_FINDING_REACHABILITY_SCOPE_LINK",
    "CREATE VIEW RBVM.ACTIVE_FINDING_REACHABILITY_SCOPE_LINK",
    "CREATE VIEW RBVM.CURRENT_FINDING_BUSINESS_SERVICE_LINK",
    "CREATE VIEW RBVM.ACTIVE_FINDING_BUSINESS_SERVICE_LINK",
):
    if needle not in sql:
        raise AssertionError(f"V21 finding-context migration missing {needle!r}")

for needle in (
    "REFERENCESRBVM.EXPOSURE(TENANT_ID,ID)",
    "LINK_STATUSIN('LINKED','UNLINKED')",
    "LINK_METHOD='CUSTOMER_CONFIRMED'",
    "TARGET_PORT_KEYINTEGERGENERATEDALWAYSAS(COALESCE(TARGET_PORT,0))STORED",
    "TRANSPORT_PROTOCOLIN('TCP','UDP','ICMP','OTHER','UNKNOWN')",
    "ORIGIN_SCOPEIN('INTERNET','EXTERNAL_PARTNER','INTERNAL_ENTERPRISE','LOCAL_SEGMENT','OTHER','UNKNOWN')",
    "WHERELINK_STATUS='LINKED'",
):
    if needle not in compact_sql:
        raise AssertionError(f"V21 finding-context semantic invariant missing {needle!r}")

for needle in (
    "UNIQUE(TENANT_ID,FINDING_ID,ORIGIN_SCOPE,ORIGIN_LABEL_NORMALIZED,TRANSPORT_PROTOCOL,TARGET_PORT_KEY,REVISION)",
    "UNIQUE(TENANT_ID,FINDING_ID,BUSINESS_SERVICE_NORMALIZED,REVISION)",
    "ORDERBYTENANT_ID,FINDING_ID,ORIGIN_SCOPE,ORIGIN_LABEL_NORMALIZED,TRANSPORT_PROTOCOL,TARGET_PORT_KEY,REVISIONDESC",
    "ORDERBYTENANT_ID,FINDING_ID,BUSINESS_SERVICE_NORMALIZED,REVISIONDESC",
):
    if needle not in compact_sql:
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
    marker = f"REVOKEUPDATE,DELETE,TRUNCATEON{relation}FROMRBVM_RUNTIME"
    if marker not in compact_runtime:
        raise AssertionError(f"runtime append-only guard missing for {relation}")

if 'new Migration(21, "V21__finding_context_association.sql")' not in migrator:
    raise AssertionError("PostgresMigrator does not register V21 finding-context association")

if not sql.startswith("BEGIN;") or not sql.endswith("COMMIT;"):
    raise AssertionError("V21 association migration must be transaction-wrapped")

print("V21 finding context association SQL checks: PASS")
