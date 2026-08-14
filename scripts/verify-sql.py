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
    v1_path = root / "db/migration/V1__canonical_rbvm.sql"
    v2_path = root / "db/migration/V2__dashboard_views.sql"
    v3_path = root / "db/migration/V3__case_workflow_audit.sql"
    v4_path = root / "db/migration/V4__postgres_projection_runtime.sql"
    v5_path = root / "db/migration/V5__postgres_read_catalog.sql"
    v6_path = root / "db/migration/V6__explicit_finding_lifecycle.sql"
    v7_path = root / "db/migration/V7__vulnerability_intelligence.sql"
    v1 = lexical_check(v1_path)
    v2 = lexical_check(v2_path)
    v3 = lexical_check(v3_path)
    v4 = lexical_check(v4_path)
    v5 = lexical_check(v5_path)
    v6 = lexical_check(v6_path)
    v7 = lexical_check(v7_path)

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
