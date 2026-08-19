#!/usr/bin/env python3
"""One-shot deterministic wiring for V14 network reachability persistence."""

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
        '            new Migration(13, "V13__asset_context_persistence.sql")\n',
        '            new Migration(13, "V13__asset_context_persistence.sql"),\n'
        '            new Migration(14, "V14__network_reachability_persistence.sql")\n',
        "migrator V14 registration",
    )


def runtime_role() -> None:
    path = ROOT / "db/security/runtime-role.sql"
    replace_once(
        path,
        "    rbvm.asset_context_snapshot,\n    rbvm.asset_context_evidence\nTO rbvm_runtime;\n",
        "    rbvm.asset_context_snapshot,\n    rbvm.asset_context_evidence,\n"
        "    rbvm.network_reachability_snapshot,\n    rbvm.network_reachability_evidence\n"
        "TO rbvm_runtime;\n",
        "runtime reachability history grants",
    )
    replace_once(
        path,
        "    rbvm.current_asset_context_evidence,\n    rbvm.finding_asset_context_evidence\nTO rbvm_runtime;\n",
        "    rbvm.current_asset_context_evidence,\n    rbvm.finding_asset_context_evidence,\n"
        "    rbvm.current_network_reachability_evidence,\n"
        "    rbvm.finding_network_reachability_evidence\nTO rbvm_runtime;\n",
        "runtime reachability view grants",
    )
    replace_once(
        path,
        "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.asset_context_evidence FROM rbvm_runtime;\n",
        "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.asset_context_evidence FROM rbvm_runtime;\n"
        "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.network_reachability_snapshot FROM rbvm_runtime;\n"
        "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.network_reachability_evidence FROM rbvm_runtime;\n",
        "runtime reachability immutability",
    )


def foundation_test() -> None:
    path = ROOT / "src/test/java/io/rbvm/postgres/PostgresFoundationSelfTest.java"
    replace_once(
        path,
        '            "/db/migration/V13__asset_context_persistence.sql"\n',
        '            "/db/migration/V13__asset_context_persistence.sql",\n'
        '            "/db/migration/V14__network_reachability_persistence.sql"\n',
        "foundation V14 resource",
    )
    replace_once(
        path,
        "        assetContextPersistencePreservesEvidenceSemantics();\n",
        "        assetContextPersistencePreservesEvidenceSemantics();\n"
        "        networkReachabilityPersistencePreservesEvidenceSemantics();\n",
        "foundation V14 semantic test call",
    )
    replace_once(
        path,
        "        PostgresAssetContextImporterSelfTest.main(args);\n",
        "        PostgresAssetContextImporterSelfTest.main(args);\n"
        "        PostgresNetworkReachabilityImporterSelfTest.main(args);\n",
        "foundation V14 importer self-test",
    )
    marker = "    private static String resource(String name) throws Exception {\n"
    method = '''    private static void networkReachabilityPersistencePreservesEvidenceSemantics() throws Exception {
        String script = resource("/db/migration/V14__network_reachability_persistence.sql");
        assert script.contains("CREATE TABLE rbvm.network_reachability_snapshot");
        assert script.contains("CREATE TABLE rbvm.network_reachability_evidence");
        assert script.contains("UNIQUE (tenant_id, evidence_source, observed_at)");
        assert script.contains("COALESCE(target_port, 0)");
        assert script.contains("target_port BETWEEN 1 AND 65535");
        assert script.contains("target_port IS NOT NULL");
        assert script.contains("transport_protocol = 'ICMP' AND target_port IS NULL");
        assert script.contains("REFERENCES rbvm.asset(tenant_id, id)");
        assert script.contains("REFERENCES rbvm.network_reachability_snapshot(tenant_id, id)");
        assert script.contains("reachability_status IN ('REACHABLE', 'NOT_REACHABLE', 'UNKNOWN')");
        assert script.contains("DISTINCT ON (");
        assert script.contains("s.evidence_source");
        assert script.contains("s.observed_at DESC");
        assert script.contains("(r.id IS NOT NULL) AS network_reachability_observed");
        assert script.contains("Missing evidence remains NULL/false");
        assert !script.contains("COALESCE(r.reachability_status, 'NOT_REACHABLE')");
        assert !script.contains("internet_exposed");
        assert !script.contains("risk_score");
        assert !script.contains("priority_tier");
        assert !script.contains("SLA_Days");
        assert !script.contains("business_criticality");
        assert !script.contains("epss_probability");
        assert !script.contains("known_exploited");
    }

'''
    replace_once(path, marker, method + marker, "foundation V14 semantic method")


def migrator_test() -> None:
    path = ROOT / "src/test/java/io/rbvm/postgres/PostgresMigratorSelfTest.java"
    text = path.read_text(encoding="utf-8")
    text = text.replace("assert migrator.migrate() == 13;", "assert migrator.migrate() == 14;")
    text = text.replace("assert database.checksums.size() == 13;", "assert database.checksums.size() == 14;")
    text = text.replace("assert database.commits == 13;", "assert database.commits == 14;")
    if 'CREATE TABLE rbvm.network_reachability_snapshot' not in text:
        anchor = '''        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_asset_context_evidence"));
'''
        addition = anchor + '''        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_snapshot"));
        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_evidence"));
        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_network_reachability_evidence"));
        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_network_reachability_evidence"));
'''
        if text.count(anchor) != 1:
            raise RuntimeError("migrator V14 create assertions anchor mismatch")
        text = text.replace(anchor, addition, 1)

        count_anchor = '''        long assetContextEvidenceCreates = database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.asset_context_evidence")).count();
'''
        count_add = count_anchor + '''        long networkReachabilitySnapshotCreates = database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_snapshot")).count();
        long networkReachabilityEvidenceCreates = database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_evidence")).count();
'''
        if text.count(count_anchor) != 1:
            raise RuntimeError("migrator V14 count anchor mismatch")
        text = text.replace(count_anchor, count_add, 1)

        replay_anchor = '''        assert database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.asset_context_evidence")).count()
                == assetContextEvidenceCreates;
'''
        replay_add = replay_anchor + '''        assert database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_snapshot")).count()
                == networkReachabilitySnapshotCreates;
        assert database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_evidence")).count()
                == networkReachabilityEvidenceCreates;
'''
        if text.count(replay_anchor) != 1:
            raise RuntimeError("migrator V14 replay anchor mismatch")
        text = text.replace(replay_anchor, replay_add, 1)
    path.write_text(text, encoding="utf-8")


def sql_verifier() -> None:
    path = ROOT / "scripts/verify-sql.py"
    text = path.read_text(encoding="utf-8")
    anchor = '            (13, "V13__asset_context_persistence.sql"),\n'
    if text.count(anchor) != 1:
        raise RuntimeError("verify-sql V14 migration anchor mismatch")
    text = text.replace(
        anchor,
        anchor + '            (14, "V14__network_reachability_persistence.sql"),\n',
        1,
    )
    anchor = "    v13 = migrations[13]\n"
    if text.count(anchor) != 1:
        raise RuntimeError("verify-sql V14 variable anchor mismatch")
    text = text.replace(anchor, anchor + "    v14 = migrations[14]\n", 1)

    marker = "    runtime_role = \" \".join(\n"
    block = '''    for invariant in (
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

'''
    if text.count(marker) != 1:
        raise RuntimeError("verify-sql V14 invariant insertion anchor mismatch")
    text = text.replace(marker, block + marker, 1)

    relation_anchor = '        "RBVM.FINDING_ASSET_CONTEXT_EVIDENCE",\n'
    if text.count(relation_anchor) != 1:
        raise RuntimeError("verify-sql V14 relation grant anchor mismatch")
    text = text.replace(
        relation_anchor,
        relation_anchor
        + '        "RBVM.NETWORK_REACHABILITY_SNAPSHOT",\n'
        + '        "RBVM.NETWORK_REACHABILITY_EVIDENCE",\n'
        + '        "RBVM.CURRENT_NETWORK_REACHABILITY_EVIDENCE",\n'
        + '        "RBVM.FINDING_NETWORK_REACHABILITY_EVIDENCE",\n',
        1,
    )
    immutable_anchor = '        "RBVM.ASSET_CONTEXT_EVIDENCE",\n'
    if text.count(immutable_anchor) != 1:
        raise RuntimeError("verify-sql V14 immutable relation anchor mismatch")
    text = text.replace(
        immutable_anchor,
        immutable_anchor
        + '        "RBVM.NETWORK_REACHABILITY_SNAPSHOT",\n'
        + '        "RBVM.NETWORK_REACHABILITY_EVIDENCE",\n',
        1,
    )
    path.write_text(text, encoding="utf-8")


def main() -> None:
    migrator()
    runtime_role()
    foundation_test()
    migrator_test()
    sql_verifier()
    print("V14 reachability persistence wiring applied")


if __name__ == "__main__":
    main()
