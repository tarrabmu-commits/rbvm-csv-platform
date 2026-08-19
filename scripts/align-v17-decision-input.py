#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def migrator() -> None:
    path = ROOT / "src/main/java/io/rbvm/postgres/PostgresMigrator.java"
    replace_once(
        path,
        '            new Migration(16, "V16__decision_methodology_policy_persistence.sql")\n',
        '            new Migration(16, "V16__decision_methodology_policy_persistence.sql"),\n'
        '            new Migration(17, "V17__decision_input_snapshot_persistence.sql")\n',
        "migrator V17 registration",
    )


def runtime_role() -> None:
    path = ROOT / "db/security/runtime-role.sql"
    replace_once(
        path,
        "    rbvm.decision_methodology_policy,\n"
        "    rbvm.decision_methodology_evidence_policy,\n"
        "    rbvm.decision_methodology_source_allowlist\n"
        "TO rbvm_runtime;\n",
        "    rbvm.decision_methodology_policy,\n"
        "    rbvm.decision_methodology_evidence_policy,\n"
        "    rbvm.decision_methodology_source_allowlist,\n"
        "    rbvm.decision_input_snapshot,\n"
        "    rbvm.decision_input_dimension,\n"
        "    rbvm.decision_input_evidence_reference\n"
        "TO rbvm_runtime;\n",
        "V17 runtime grants",
    )
    replace_once(
        path,
        "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.decision_methodology_source_allowlist FROM rbvm_runtime;\n",
        "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.decision_methodology_source_allowlist FROM rbvm_runtime;\n"
        "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.decision_input_snapshot FROM rbvm_runtime;\n"
        "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.decision_input_dimension FROM rbvm_runtime;\n"
        "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.decision_input_evidence_reference FROM rbvm_runtime;\n",
        "V17 append-only revokes",
    )


def foundation() -> None:
    path = ROOT / "src/test/java/io/rbvm/postgres/PostgresFoundationSelfTest.java"
    replace_once(
        path,
        '            "/db/migration/V15__business_impact_persistence.sql"\n',
        '            "/db/migration/V15__business_impact_persistence.sql",\n'
        '            "/db/migration/V16__decision_methodology_policy_persistence.sql",\n'
        '            "/db/migration/V17__decision_input_snapshot_persistence.sql"\n',
        "foundation migration resources",
    )
    replace_once(
        path,
        "        PostgresBusinessImpactImporterSelfTest.main(args);\n",
        "        PostgresBusinessImpactImporterSelfTest.main(args);\n"
        "        PostgresDecisionMethodologyPolicyStoreSelfTest.main(args);\n"
        "        PostgresDecisionInputSnapshotStoreSelfTest.main(args);\n",
        "foundation decision persistence self-tests",
    )


def migrator_test() -> None:
    path = ROOT / "src/test/java/io/rbvm/postgres/PostgresMigratorSelfTest.java"
    text = path.read_text(encoding="utf-8")
    for old, new, label in (
        ("assert migrator.migrate() == 16;", "assert migrator.migrate() == 17;", "migrate version assertions"),
        ("assert database.checksums.size() == 16;", "assert database.checksums.size() == 17;", "checksum count"),
        ("assert database.commits == 16;", "assert database.commits == 17;", "initial commit count"),
        ('        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.decision_methodology_source_allowlist"));\n',
         '        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.decision_methodology_source_allowlist"));\n'
         '        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.decision_input_snapshot"));\n'
         '        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.decision_input_dimension"));\n'
         '        assert database.executedSql.stream().anyMatch(sql -> sql.contains("CREATE TABLE rbvm.decision_input_evidence_reference"));\n',
         "V17 create assertions"),
        ('        long methodologyAllowlistCreates = count(database, "CREATE TABLE rbvm.decision_methodology_source_allowlist");\n',
         '        long methodologyAllowlistCreates = count(database, "CREATE TABLE rbvm.decision_methodology_source_allowlist");\n'
         '        long decisionInputSnapshotCreates = count(database, "CREATE TABLE rbvm.decision_input_snapshot");\n'
         '        long decisionInputDimensionCreates = count(database, "CREATE TABLE rbvm.decision_input_dimension");\n'
         '        long decisionInputReferenceCreates = count(database, "CREATE TABLE rbvm.decision_input_evidence_reference");\n',
         "V17 create counters"),
        ('        assert count(database, "CREATE TABLE rbvm.decision_methodology_source_allowlist") == methodologyAllowlistCreates;\n',
         '        assert count(database, "CREATE TABLE rbvm.decision_methodology_source_allowlist") == methodologyAllowlistCreates;\n'
         '        assert count(database, "CREATE TABLE rbvm.decision_input_snapshot") == decisionInputSnapshotCreates;\n'
         '        assert count(database, "CREATE TABLE rbvm.decision_input_dimension") == decisionInputDimensionCreates;\n'
         '        assert count(database, "CREATE TABLE rbvm.decision_input_evidence_reference") == decisionInputReferenceCreates;\n',
         "V17 replay counters"),
    ):
        count = text.count(old)
        if label == "migrate version assertions":
            if count != 2:
                raise RuntimeError(f"{label}: expected two anchors, found {count}")
            text = text.replace(old, new)
        else:
            if count != 1:
                raise RuntimeError(f"{label}: expected one anchor, found {count}")
            text = text.replace(old, new, 1)
    # Replay commit count must remain the number of applied migrations after the first call.
    old = '        assert database.commits == 16 : "replay must not reapply migrations";\n'
    new = '        assert database.commits == 17 : "replay must not reapply migrations";\n'
    if text.count(old) != 1:
        raise RuntimeError("V17 replay commit count anchor mismatch")
    text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")


def verify_sh() -> None:
    path = ROOT / "scripts/verify.sh"
    replace_once(
        path,
        'python3 "$ROOT_DIR/scripts/verify-decision-methodology-sql.py"\n',
        'python3 "$ROOT_DIR/scripts/verify-decision-methodology-sql.py"\n'
        'python3 "$ROOT_DIR/scripts/verify-decision-input-snapshot-sql.py"\n',
        "V17 verifier wiring",
    )


def main() -> None:
    migrator()
    runtime_role()
    foundation()
    migrator_test()
    verify_sh()
    print("V17 decision-input persistence wiring applied")


if __name__ == "__main__":
    main()
