#!/usr/bin/env python3
from pathlib import Path


def normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split()).upper()


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    migration = normalized(root / "db/migration/V16__decision_methodology_policy_persistence.sql")
    runtime = normalized(root / "db/security/runtime-role.sql")
    migrator = (root / "src/main/java/io/rbvm/postgres/PostgresMigrator.java").read_text(
        encoding="utf-8"
    )

    if 'new Migration(16, "V16__decision_methodology_policy_persistence.sql")' not in migrator:
        raise AssertionError("PostgresMigrator must register V16 methodology policy persistence")

    for invariant in (
        "CREATE TABLE RBVM.DECISION_METHODOLOGY_POLICY",
        "CREATE TABLE RBVM.DECISION_METHODOLOGY_EVIDENCE_POLICY",
        "CREATE TABLE RBVM.DECISION_METHODOLOGY_SOURCE_ALLOWLIST",
        "CONTRACT_ID = 'RBVM_DECISION_METHODOLOGY_V1'",
        "SEMANTICS = 'FINDING_SCOPED_EXPLICIT_EVIDENCE_SELECTION_POLICY'",
        "CANONICAL_PAYLOAD_FORMAT = 'RBVM_DECISION_METHODOLOGY_CANONICAL_BINARY_V1'",
        "SUBJECT_SCOPE = 'FINDING'",
        "MISSING_EVIDENCE_HANDLING = 'PRESERVE_UNKNOWN'",
        "AMBIGUITY_HANDLING = 'PRESERVE_AMBIGUOUS'",
        "LEGACY_PRIORITY_HANDLING = 'EXCLUDE_LEGACY_PRIORITY_TIER'",
        "UNIQUE (TENANT_ID, CONTRACT_ID, REVISION)",
        "SOURCE_SELECTION_MODE IN ('ALL_SOURCES', 'EXPLICIT_ALLOWLIST')",
        "FRESHNESS_MODE IN ('NO_AGE_LIMIT', 'MAX_AGE_SECONDS')",
        "MAXIMUM_AGE_SECONDS IS NOT NULL AND MAXIMUM_AGE_SECONDS > 0",
        "BUSINESS_MISSION_IMPACT",
        "REFERENCES RBVM.DECISION_METHODOLOGY_POLICY(TENANT_ID, ID)",
        "REFERENCES RBVM.DECISION_METHODOLOGY_EVIDENCE_POLICY",
    ):
        if invariant not in migration:
            raise AssertionError(f"V16 is missing methodology registry invariant: {invariant}")

    # Policy selection/activation is deliberately not inferred by SQL.
    for forbidden in (
        "CREATE VIEW RBVM.CURRENT_DECISION_METHODOLOGY",
        "CREATE VIEW RBVM.ACTIVE_DECISION_METHODOLOGY",
        "IS_ACTIVE",
        "ACTIVE_POLICY",
        "MAX(REVISION)",
        "RISK_SCORE",
        "PRIORITY_TIER",
        "SLA_DAYS",
        "IMPACT_WEIGHT",
        "AGGREGATE_IMPACT_SCORE",
        "ATTACK_PATH_SCORE",
        "INTERNET_EXPOSED",
    ):
        if forbidden in migration:
            raise AssertionError(f"V16 must not derive or select {forbidden}")

    relations = (
        "RBVM.DECISION_METHODOLOGY_POLICY",
        "RBVM.DECISION_METHODOLOGY_EVIDENCE_POLICY",
        "RBVM.DECISION_METHODOLOGY_SOURCE_ALLOWLIST",
    )
    for relation in relations:
        if relation not in runtime:
            raise AssertionError(f"runtime role is missing methodology registry relation {relation}")
        marker = f"REVOKE UPDATE, DELETE, TRUNCATE ON {relation} FROM RBVM_RUNTIME"
        if marker not in runtime:
            raise AssertionError(f"runtime role must keep {relation} append-only")

    print("Decision methodology V16 SQL structural checks: PASS")


if __name__ == "__main__":
    main()
