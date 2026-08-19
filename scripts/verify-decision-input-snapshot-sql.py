#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MIGRATION = ROOT / "db/migration/V17__decision_input_snapshot_persistence.sql"
ROLE = ROOT / "db/security/runtime-role.sql"
MIGRATOR = ROOT / "src/main/java/io/rbvm/postgres/PostgresMigrator.java"


def normalize_text(value: str) -> str:
    return " ".join(value.split()).upper()


def normalized(path: Path) -> str:
    return normalize_text(path.read_text(encoding="utf-8"))


def sql_without_comments(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"--[^\n]*", " ", text)
    return normalize_text(text)


def main() -> None:
    migration = normalized(MIGRATION)
    migration_code = sql_without_comments(MIGRATION)
    role = normalized(ROLE)
    migrator = MIGRATOR.read_text(encoding="utf-8")

    required = (
        "ALTER TABLE RBVM.DECISION_METHODOLOGY_POLICY",
        "UNIQUE (TENANT_ID, ID, REVISION, POLICY_SHA256)",
        "CREATE TABLE RBVM.DECISION_INPUT_SNAPSHOT",
        "CREATE TABLE RBVM.DECISION_INPUT_DIMENSION",
        "CREATE TABLE RBVM.DECISION_INPUT_EVIDENCE_REFERENCE",
        "UNIQUE (TENANT_ID, FINDING_ID, METHODOLOGY_POLICY_ID, EVALUATED_AT)",
        "UNIQUE (TENANT_ID, SNAPSHOT_SHA256)",
        "REFERENCES RBVM.EXPOSURE(TENANT_ID, ID)",
        "REFERENCES RBVM.DECISION_METHODOLOGY_POLICY",
        "FINDING_SCOPED_POLICY_BOUND_EVIDENCE_REFERENCE_SNAPSHOT",
        "RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V1",
        "DIMENSION_STATE IN ('PRESENT', 'MISSING', 'AMBIGUOUS', 'STALE')",
        "PRIMARY KEY (TENANT_ID, SNAPSHOT_ID, EVIDENCE_DIMENSION, EVIDENCE_ID)",
    )
    for marker in required:
        if marker not in migration:
            raise AssertionError(f"V17 is missing required invariant: {marker}")

    for forbidden in (
        "RISK_SCORE",
        "PRIORITY_TIER",
        "SLA_DAYS",
        "TREATMENT",
        "WEIGHT",
        "MULTIPLIER",
        "COEFFICIENT",
        "THRESHOLD",
        "MONETARY_LOSS",
        "INTERNET_EXPOSED",
        "ATTACK_PATH",
        "ACTIVE_POLICY",
        "CURRENT_POLICY",
        "MAX(REVISION)",
    ):
        if forbidden in migration_code:
            raise AssertionError(f"V17 must not derive or persist {forbidden}")

    for relation in (
        "RBVM.DECISION_INPUT_SNAPSHOT",
        "RBVM.DECISION_INPUT_DIMENSION",
        "RBVM.DECISION_INPUT_EVIDENCE_REFERENCE",
    ):
        if relation not in role:
            raise AssertionError(f"runtime role is missing {relation}")
        marker = f"REVOKE UPDATE, DELETE, TRUNCATE ON {relation} FROM RBVM_RUNTIME"
        if marker not in role:
            raise AssertionError(f"runtime role must keep {relation} append-only")

    if 'new Migration(17, "V17__decision_input_snapshot_persistence.sql")' not in migrator:
        raise AssertionError("PostgresMigrator does not register V17")

    print("Decision Input Snapshot SQL verification: PASS")


if __name__ == "__main__":
    main()
