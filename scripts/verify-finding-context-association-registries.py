#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

reachability_api = (
    ROOT / "src/main/java/io/rbvm/context/FindingReachabilityScopeLinkRegistry.java"
).read_text(encoding="utf-8")
service_api = (
    ROOT / "src/main/java/io/rbvm/context/FindingBusinessServiceLinkRegistry.java"
).read_text(encoding="utf-8")
reachability_pg = (
    ROOT / "src/main/java/io/rbvm/postgres/PostgresFindingReachabilityScopeLinkRegistry.java"
).read_text(encoding="utf-8")
service_pg = (
    ROOT / "src/main/java/io/rbvm/postgres/PostgresFindingBusinessServiceLinkRegistry.java"
).read_text(encoding="utf-8")
live = (
    ROOT / "src/test/java/io/rbvm/postgres/PostgresV21LiveSelfTest.java"
).read_text(encoding="utf-8")

for name, text in (
    ("reachability registry API", reachability_api),
    ("business-service registry API", service_api),
):
    for needle in (
        "UPDATED",
        "REPLAYED",
        "FINDING_NOT_FOUND",
        "REVISION_CONFLICT",
        "expectedRevision",
        "history(",
        "listCurrent(",
    ):
        if needle not in text:
            raise AssertionError(f"{name} is missing {needle!r}")

for name, text, table, view in (
    (
        "reachability PostgreSQL registry",
        reachability_pg,
        "rbvm.finding_reachability_scope_link_event",
        "rbvm.current_finding_reachability_scope_link",
    ),
    (
        "business-service PostgreSQL registry",
        service_pg,
        "rbvm.finding_business_service_link_event",
        "rbvm.current_finding_business_service_link",
    ),
):
    for needle in (
        "REQUIRED_SCHEMA_VERSION = 21",
        "Connection.TRANSACTION_SERIALIZABLE",
        "pg_advisory_xact_lock(?)",
        "currentRevision == expectedRevision + 1",
        "current.sameCustomerState(nextState)",
        "MutationStatus.REPLAYED",
        "MutationStatus.REVISION_CONFLICT",
        "MutationStatus.FINDING_NOT_FOUND",
        "SELECT 1 FROM rbvm.exposure WHERE tenant_id = ? AND id = ?",
        table,
        view,
    ):
        if needle not in text:
            raise AssertionError(f"{name} is missing {needle!r}")
    for forbidden in (
        f"UPDATE {table}",
        f"DELETE FROM {table}",
        "RISK_SCORE",
        "PRIORITY_TIER",
        "SLA_DAYS",
        "AUTO_LINK",
        "AUTO_MATCH",
    ):
        if forbidden in text:
            raise AssertionError(f"{name} must not contain {forbidden!r}")

for needle in (
    "PostgresFindingReachabilityScopeLinkRegistry",
    "PostgresFindingBusinessServiceLinkRegistry",
    "MutationStatus.UPDATED",
    "MutationStatus.REPLAYED",
    "MutationStatus.REVISION_CONFLICT",
    "MutationStatus.FINDING_NOT_FOUND",
    "history(",
    "listCurrent(",
    "runtime role must not UPDATE Finding reachability association history",
    "runtime role must not DELETE Finding business-service association history",
):
    if needle not in live:
        raise AssertionError(f"V21 live integration is missing registry proof {needle!r}")

print("Finding context association registry structural checks: PASS")
