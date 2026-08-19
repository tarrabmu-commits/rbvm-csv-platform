#!/usr/bin/env python3
from pathlib import Path
import sys


def lexical_check(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    state = "normal"
    depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "normal":
            if char == "'":
                state = "single"
            elif char == '"':
                state = "double"
            elif char == "-" and following == "-":
                state = "line_comment"
                index += 1
            elif char == "/" and following == "*":
                state = "block_comment"
                index += 1
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth < 0:
                    raise AssertionError(f"{path}: unmatched closing parenthesis")
        elif state == "single":
            if char == "'" and following == "'":
                index += 1
            elif char == "'":
                state = "normal"
        elif state == "double":
            if char == '"' and following == '"':
                index += 1
            elif char == '"':
                state = "normal"
        elif state == "line_comment":
            if char == "\n":
                state = "normal"
        elif state == "block_comment":
            if char == "*" and following == "/":
                state = "normal"
                index += 1
        index += 1

    if state not in {"normal", "line_comment"}:
        raise AssertionError(f"{path}: unterminated SQL lexical state {state}")
    if depth != 0:
        raise AssertionError(f"{path}: unbalanced parentheses ({depth})")
    normalized = " ".join(text.split()).upper()
    if not normalized.startswith("BEGIN;") or not normalized.endswith("COMMIT;"):
        raise AssertionError(f"{path}: migration must be transaction-wrapped")
    destructive = ("DROP TABLE", "DROP SCHEMA", "DROP COLUMN", "TRUNCATE ", " CASCADE")
    if any(token in normalized for token in destructive):
        raise AssertionError(f"{path}: destructive data SQL is forbidden in these migrations")
    return normalized


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    migrations = {
        version: lexical_check(root / f"db/migration/{name}")
        for version, name in (
            (1, "V1__canonical_rbvm.sql"),
            (2, "V2__dashboard_views.sql"),
            (3, "V3__case_workflow_audit.sql"),
            (4, "V4__postgres_projection_runtime.sql"),
            (5, "V5__postgres_read_catalog.sql"),
            (6, "V6__explicit_finding_lifecycle.sql"),
            (7, "V7__vulnerability_intelligence.sql"),
            (8, "V8__operational_analytics.sql"),
            (9, "V9__applicability_persistence.sql"),
            (10, "V10__cvss_v31_base_persistence.sql"),
            (11, "V11__cisa_kev_persistence.sql"),
            (12, "V12__epss_persistence.sql"),
            (13, "V13__asset_context_persistence.sql"),
            (14, "V14__network_reachability_persistence.sql"),
        )
    }
    v1, v2, v3, v4, v5, v6, v7 = (migrations[index] for index in range(1, 8))
    v11 = migrations[11]
    v12 = migrations[12]
    v13 = migrations[13]
    v14 = migrations[14]

    required_tables = {
        "tenant",
        "source_profile",
        "import_run",
        "api_idempotency_key",
        "asset",
        "vulnerability",
        "asset_component",
        "observation",
        "import_observation",
        "observation_reference",
        "vulnerability_case",
        "exposure",
        "exposure_observation",
        "validation_issue",
    }
    for table in required_tables:
        marker = f"CREATE TABLE RBVM.{table.upper()} "
        if marker not in v1:
            raise AssertionError(f"V1 is missing table {table}")
    for view in ("case_dashboard", "import_reconciliation"):
        if f"CREATE VIEW RBVM.{view.upper()} " not in v2:
            raise AssertionError(f"V2 is missing view {view}")
    if "CREATE TABLE RBVM.CASE_AUDIT_EVENT " not in v3:
        raise AssertionError("V3 is missing table case_audit_event")
    if "CREATE VIEW RBVM.CASE_WORKFLOW_RECONCILIATION " not in v3:
        raise AssertionError("V3 is missing workflow reconciliation view")
    for table in ("domain_materialization", "catalog_state"):
        if f"CREATE TABLE RBVM.{table.upper()} " not in v4:
            raise AssertionError(f"V4 is missing table {table}")
    if "CREATE VIEW RBVM.POSTGRES_PROJECTION_RECONCILIATION " not in v4:
        raise AssertionError("V4 is missing PostgreSQL projection reconciliation view")
    if "CREATE SEQUENCE RBVM.CASE_AUDIT_EVENT_DATABASE_SEQUENCE" not in v4:
        raise AssertionError("V4 is missing the database-global audit sequence")
    for invariant in (
        "UNIQUE (TENANT_ID, CASE_ID, CASE_VERSION)",
        "UNIQUE (TENANT_ID, CASE_ID, IDEMPOTENCY_KEY)",
        "UNAUTHENTICATED_LOCAL",
        "ACTION_TYPE <> 'CLOSE_MANUAL'",
    ):
        if invariant not in v3:
            raise AssertionError(f"V3 is missing workflow invariant {invariant}")
    for invariant in (
        "PUBLIC_ID CHAR(64)",
        "SOURCE_SEQUENCE BIGINT",
        "CHECK (ACCEPTED_OBSERVATIONS = INSERTED_OBSERVATIONS + DUPLICATE_OBSERVATIONS)",
        "NOT VALID",
    ):
        if invariant not in v4:
            raise AssertionError(f"V4 is missing projection invariant {invariant}")
    for invariant in (
        "VULNERABILITY_CASE_CATALOG_ORDER_IDX",
        "EXPOSURE_CASE_CATALOG_ORDER_IDX",
        "CASE_AUDIT_EVENT_APPEND_ONLY",
        "REJECT_CASE_AUDIT_EVENT_MUTATION",
    ):
        if invariant not in v5:
            raise AssertionError(f"V5 is missing read-cutover invariant {invariant}")
    for invariant in (
        "WAZUH_CSV_V2",
        "EXPLICIT_FINDING_LIFECYCLE_EXPORT",
        "SOURCE_STABLE_ID",
        "OBSERVED_FROM_SOURCE",
        "SOURCE_RESOLVED",
        "EXPLICIT_SOURCE_EVIDENCE_ONLY",
        "OBSERVATION_LIFECYCLE_EVIDENCE_CHECK",
    ):
        if invariant not in v6:
            raise AssertionError(f"V6 is missing lifecycle invariant {invariant}")
    for invariant in (
        "CVSS_BASE_SCORE", "EPSS_PROBABILITY", "KNOWN_EXPLOITED",
        "INTELLIGENCE_OBSERVED_AT", "PRIORITY_TIER", "VULNERABILITY_PRIORITY_IDX",
    ):
        if invariant not in v7:
            raise AssertionError(f"V7 is missing intelligence invariant {invariant}")

    for invariant in (
        "CREATE TABLE RBVM.CISA_KEV_CATALOG_SNAPSHOT",
        "CREATE TABLE RBVM.CISA_KEV_EVIDENCE",
        "UNIQUE (TENANT_ID, KEV_SOURCE, OBSERVED_AT)",
        "UNIQUE (TENANT_ID, VULNERABILITY_ID, SNAPSHOT_ID)",
        "REFERENCES RBVM.CISA_KEV_CATALOG_SNAPSHOT(TENANT_ID, ID)",
        "KEV_STATUS IN ('LISTED', 'NOT_LISTED')",
        "CREATE VIEW RBVM.CURRENT_CISA_KEV_EVIDENCE",
        "CREATE VIEW RBVM.FINDING_CISA_KEV_EVIDENCE",
        "COALESCE(K.KEV_STATUS, 'UNKNOWN')",
    ):
        if invariant not in v11:
            raise AssertionError(f"V11 is missing KEV persistence invariant {invariant}")
    for forbidden in ("PRIORITY_TIER", "RISK_SCORE", "EPSS_PROBABILITY", "SLA_DAYS"):
        if forbidden in v11:
            raise AssertionError(f"V11 must not derive {forbidden}")

    for invariant in (
        "CREATE TABLE RBVM.EPSS_SCORE_SNAPSHOT",
        "CREATE TABLE RBVM.EPSS_EVIDENCE",
        "UNIQUE (TENANT_ID, EPSS_SOURCE, OBSERVED_AT)",
        "UNIQUE (TENANT_ID, VULNERABILITY_ID, SNAPSHOT_ID)",
        "REFERENCES RBVM.EPSS_SCORE_SNAPSHOT(TENANT_ID, ID)",
        "EPSS_PROBABILITY >= 0 AND EPSS_PROBABILITY <= 1",
        "EPSS_PERCENTILE >= 0 AND EPSS_PERCENTILE <= 1",
        "CREATE VIEW RBVM.CURRENT_EPSS_EVIDENCE",
        "CREATE VIEW RBVM.FINDING_EPSS_EVIDENCE",
        "DISTINCT ON (E.TENANT_ID, E.VULNERABILITY_ID, S.EPSS_SOURCE)",
        "S.SCORE_DATE DESC, S.OBSERVED_AT DESC",
        "(E.ID IS NOT NULL) AS EPSS_EVIDENCE_OBSERVED",
    ):
        if invariant not in v12:
            raise AssertionError(f"V12 is missing EPSS persistence invariant {invariant}")
    for forbidden in ("PRIORITY_TIER", "RISK_SCORE", "SLA_DAYS"):
        if forbidden in v12:
            raise AssertionError(f"V12 must not derive {forbidden}")
    if "COALESCE(E.EPSS_PROBABILITY" in v12:
        raise AssertionError("V12 must preserve missing EPSS as absence, not probability zero")

    for invariant in (
        "CREATE TABLE RBVM.ASSET_CONTEXT_SNAPSHOT",
        "CREATE TABLE RBVM.ASSET_CONTEXT_EVIDENCE",
        "UNIQUE (TENANT_ID, CONTEXT_SOURCE, OBSERVED_AT)",
        "UNIQUE (TENANT_ID, ASSET_ID, SNAPSHOT_ID)",
        "REFERENCES RBVM.ASSET(TENANT_ID, ID)",
        "REFERENCES RBVM.ASSET_CONTEXT_SNAPSHOT(TENANT_ID, ID)",
        "ASSET_IDENTITY_BASIS IN ('SOURCE_NAME_ONLY', 'SOURCE_STABLE_ID')",
        "BUSINESS_CRITICALITY IN ('MISSION_CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN')",
        "CREATE VIEW RBVM.CURRENT_ASSET_CONTEXT_EVIDENCE",
        "CREATE VIEW RBVM.FINDING_ASSET_CONTEXT_EVIDENCE",
        "DISTINCT ON (E.TENANT_ID, E.ASSET_ID, S.CONTEXT_SOURCE)",
        "S.OBSERVED_AT DESC",
        "(C.ID IS NOT NULL) AS ASSET_CONTEXT_OBSERVED",
    ):
        if invariant not in v13:
            raise AssertionError(f"V13 is missing asset-context persistence invariant {invariant}")
    for forbidden in ("PRIORITY_TIER", "RISK_SCORE", "SLA_DAYS", "EPSS_PROBABILITY", "KNOWN_EXPLOITED"):
        if forbidden in v13:
            raise AssertionError(f"V13 must not derive {forbidden}")

    for invariant in (
        "CREATE TABLE RBVM.NETWORK_REACHABILITY_SNAPSHOT",
        "CREATE TABLE RBVM.NETWORK_REACHABILITY_EVIDENCE",
        "UNIQUE (TENANT_ID, EVIDENCE_SOURCE, OBSERVED_AT)",
        "COALESCE(TARGET_PORT, 0)",
        "TARGET_PORT BETWEEN 1 AND 65535",
        "TRANSPORT_PROTOCOL = 'ICMP' AND TARGET_PORT IS NULL",
        "REFERENCES RBVM.ASSET(TENANT_ID, ID)",
        "REFERENCES RBVM.NETWORK_REACHABILITY_SNAPSHOT(TENANT_ID, ID)",
        "REACHABILITY_STATUS IN ('REACHABLE', 'NOT_REACHABLE', 'UNKNOWN')",
        "CREATE VIEW RBVM.CURRENT_NETWORK_REACHABILITY_EVIDENCE",
        "CREATE VIEW RBVM.FINDING_NETWORK_REACHABILITY_EVIDENCE",
        "S.EVIDENCE_SOURCE",
        "S.OBSERVED_AT DESC",
        "(R.ID IS NOT NULL) AS NETWORK_REACHABILITY_OBSERVED",
    ):
        if invariant not in v14:
            raise AssertionError(f"V14 is missing network reachability persistence invariant {invariant}")
    if "COALESCE(R.REACHABILITY_STATUS, 'NOT_REACHABLE')" in v14:
        raise AssertionError("V14 must preserve missing reachability as absence, not NOT_REACHABLE")
    for forbidden in (
        "INTERNET_EXPOSED", "RISK_SCORE", "PRIORITY_TIER", "SLA_DAYS",
        "BUSINESS_CRITICALITY", "EPSS_PROBABILITY", "KNOWN_EXPLOITED"
    ):
        if forbidden in v14:
            raise AssertionError(f"V14 must not derive {forbidden}")

    runtime_role = " ".join(
        (root / "db/security/runtime-role.sql").read_text(encoding="utf-8").split()
    ).upper()
    for relation in (
        "RBVM.CISA_KEV_CATALOG_SNAPSHOT",
        "RBVM.CISA_KEV_EVIDENCE",
        "RBVM.EPSS_SCORE_SNAPSHOT",
        "RBVM.EPSS_EVIDENCE",
        "RBVM.CURRENT_CISA_KEV_EVIDENCE",
        "RBVM.FINDING_CISA_KEV_EVIDENCE",
        "RBVM.CURRENT_EPSS_EVIDENCE",
        "RBVM.FINDING_EPSS_EVIDENCE",
        "RBVM.ASSET_CONTEXT_SNAPSHOT",
        "RBVM.ASSET_CONTEXT_EVIDENCE",
        "RBVM.CURRENT_ASSET_CONTEXT_EVIDENCE",
        "RBVM.FINDING_ASSET_CONTEXT_EVIDENCE",
        "RBVM.NETWORK_REACHABILITY_SNAPSHOT",
        "RBVM.NETWORK_REACHABILITY_EVIDENCE",
        "RBVM.CURRENT_NETWORK_REACHABILITY_EVIDENCE",
        "RBVM.FINDING_NETWORK_REACHABILITY_EVIDENCE",
    ):
        if relation not in runtime_role:
            raise AssertionError(f"runtime role is missing intelligence/context relation {relation}")
    for relation in (
        "RBVM.CISA_KEV_CATALOG_SNAPSHOT",
        "RBVM.CISA_KEV_EVIDENCE",
        "RBVM.EPSS_SCORE_SNAPSHOT",
        "RBVM.EPSS_EVIDENCE",
        "RBVM.ASSET_CONTEXT_SNAPSHOT",
        "RBVM.ASSET_CONTEXT_EVIDENCE",
        "RBVM.NETWORK_REACHABILITY_SNAPSHOT",
        "RBVM.NETWORK_REACHABILITY_EVIDENCE",
    ):
        marker = f"REVOKE UPDATE, DELETE, TRUNCATE ON {relation} FROM RBVM_RUNTIME"
        if marker not in runtime_role:
            raise AssertionError(f"runtime role must keep {relation} append-only")

    read_catalog = (root / "src/main/java/io/rbvm/postgres/PostgresReadCatalog.java").read_text(
        encoding="utf-8")
    if "intel_observed_at" in read_catalog:
        raise AssertionError("PostgreSQL reads must use the V7 intelligence_observed_at column")
    for column in ("intelligence_observed_at", "known_exploited", "priority_tier"):
        if column not in read_catalog:
            raise AssertionError(f"PostgreSQL intelligence summary is missing V7 column {column}")
    for invariant in (
        "POSITIVE_ONLY_NO_AUTO_CLOSE",
        "SOURCE_NAME_ONLY",
        "UNKNOWN_FROM_SOURCE",
        "UNIQUE (TENANT_ID, SOURCE_PROFILE_ID, FINGERPRINT)",
    ):
        if invariant not in v1:
            raise AssertionError(f"V1 is missing invariant {invariant}")

    print("SQL migration structural checks: PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(error, file=sys.stderr)
        raise
