#!/usr/bin/env python3
"""Idempotently finalize V14 reachability wiring and persistence identity semantics."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(path: str) -> tuple[Path, str]:
    target = ROOT / path
    return target, target.read_text(encoding="utf-8")


def write(target: Path, text: str) -> None:
    target.write_text(text, encoding="utf-8")


def add_after_once(text: str, anchor: str, addition: str, label: str) -> str:
    if addition.strip() in text:
        return text
    if text.count(anchor) != 1:
        raise RuntimeError(f"{label}: anchor count={text.count(anchor)}")
    return text.replace(anchor, anchor + addition, 1)


def replace_once_if_present(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if text.count(old) != 1:
        raise RuntimeError(f"{label}: anchor count={text.count(old)}")
    return text.replace(old, new, 1)


def finalize_migrator() -> None:
    path, text = read("src/main/java/io/rbvm/postgres/PostgresMigrator.java")
    old = '            new Migration(13, "V13__asset_context_persistence.sql")\n'
    new = ('            new Migration(13, "V13__asset_context_persistence.sql"),\n'
           '            new Migration(14, "V14__network_reachability_persistence.sql")\n')
    text = replace_once_if_present(text, old, new, "migrator V14")
    write(path, text)


def finalize_runtime_role() -> None:
    path, text = read("db/security/runtime-role.sql")
    if "rbvm.network_reachability_snapshot" not in text:
        text = text.replace(
            "    rbvm.asset_context_snapshot,\n    rbvm.asset_context_evidence\nTO rbvm_runtime;\n",
            "    rbvm.asset_context_snapshot,\n    rbvm.asset_context_evidence,\n"
            "    rbvm.network_reachability_snapshot,\n    rbvm.network_reachability_evidence\n"
            "TO rbvm_runtime;\n",
            1,
        )
        text = text.replace(
            "    rbvm.current_asset_context_evidence,\n    rbvm.finding_asset_context_evidence\nTO rbvm_runtime;\n",
            "    rbvm.current_asset_context_evidence,\n    rbvm.finding_asset_context_evidence,\n"
            "    rbvm.current_network_reachability_evidence,\n"
            "    rbvm.finding_network_reachability_evidence\nTO rbvm_runtime;\n",
            1,
        )
        text = text.replace(
            "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.asset_context_evidence FROM rbvm_runtime;\n",
            "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.asset_context_evidence FROM rbvm_runtime;\n"
            "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.network_reachability_snapshot FROM rbvm_runtime;\n"
            "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.network_reachability_evidence FROM rbvm_runtime;\n",
            1,
        )
    for token in (
        "rbvm.network_reachability_snapshot",
        "rbvm.network_reachability_evidence",
        "rbvm.current_network_reachability_evidence",
        "rbvm.finding_network_reachability_evidence",
    ):
        if token not in text:
            raise RuntimeError(f"runtime-role missing {token}")
    write(path, text)


def finalize_importer_normalization() -> None:
    path, text = read("src/main/java/io/rbvm/postgres/PostgresNetworkReachabilityImporter.java")
    if "import java.text.Normalizer;" not in text:
        text = text.replace("import java.sql.Timestamp;\n", "import java.sql.Timestamp;\nimport java.text.Normalizer;\n", 1)
    if "import java.util.Locale;" not in text:
        text = text.replace("import java.util.List;\n", "import java.util.List;\nimport java.util.Locale;\n", 1)
    text = text.replace(
        "statement.setString(5, evidence.originLabel());",
        "statement.setString(5, normalizedOriginLabel(evidence));",
    )
    text = text.replace(
        "statement.setString(9, evidence.originLabel());",
        "statement.setString(9, normalizedOriginLabel(evidence));",
    )
    text = text.replace(
        '+ evidence.originLabel() + "\\u001F"',
        '+ normalizedOriginLabel(evidence) + "\\u001F"',
    )
    if "private static String normalizedOriginLabel(" not in text:
        marker = "    private static String evidenceSha256(NetworkReachabilityCsvEvidence evidence) {\n"
        helper = '''    private static String normalizedOriginLabel(NetworkReachabilityCsvEvidence evidence) {
        return Normalizer.normalize(evidence.originLabel().trim(), Normalizer.Form.NFKC)
                .toLowerCase(Locale.ROOT);
    }

'''
        if text.count(marker) != 1:
            raise RuntimeError("importer normalization insertion anchor mismatch")
        text = text.replace(marker, helper + marker, 1)
    write(path, text)


def finalize_foundation_test() -> None:
    path, text = read("src/test/java/io/rbvm/postgres/PostgresFoundationSelfTest.java")
    if 'V14__network_reachability_persistence.sql' not in text:
        text = text.replace(
            '            "/db/migration/V13__asset_context_persistence.sql"\n',
            '            "/db/migration/V13__asset_context_persistence.sql",\n'
            '            "/db/migration/V14__network_reachability_persistence.sql"\n',
            1,
        )
    if "networkReachabilityPersistencePreservesEvidenceSemantics();" not in text:
        text = text.replace(
            "        assetContextPersistencePreservesEvidenceSemantics();\n",
            "        assetContextPersistencePreservesEvidenceSemantics();\n"
            "        networkReachabilityPersistencePreservesEvidenceSemantics();\n",
            1,
        )
    if "PostgresNetworkReachabilityImporterSelfTest.main(args);" not in text:
        text = text.replace(
            "        PostgresAssetContextImporterSelfTest.main(args);\n",
            "        PostgresAssetContextImporterSelfTest.main(args);\n"
            "        PostgresNetworkReachabilityImporterSelfTest.main(args);\n",
            1,
        )
    if "private static void networkReachabilityPersistencePreservesEvidenceSemantics()" not in text:
        marker = "    private static String resource(String name) throws Exception {\n"
        method = '''    private static void networkReachabilityPersistencePreservesEvidenceSemantics() throws Exception {
        String script = resource("/db/migration/V14__network_reachability_persistence.sql");
        assert script.contains("CREATE TABLE rbvm.network_reachability_snapshot");
        assert script.contains("CREATE TABLE rbvm.network_reachability_evidence");
        assert script.contains("UNIQUE (tenant_id, evidence_source, observed_at)");
        assert script.contains("COALESCE(target_port, 0)");
        assert script.contains("target_port BETWEEN 1 AND 65535");
        assert script.contains("transport_protocol = 'ICMP' AND target_port IS NULL");
        assert script.contains("REFERENCES rbvm.asset(tenant_id, id)");
        assert script.contains("REFERENCES rbvm.network_reachability_snapshot(tenant_id, id)");
        assert script.contains("reachability_status IN ('REACHABLE', 'NOT_REACHABLE', 'UNKNOWN')");
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
        if text.count(marker) != 1:
            raise RuntimeError("foundation V14 method anchor mismatch")
        text = text.replace(marker, method + marker, 1)
    write(path, text)


def finalize_migrator_test() -> None:
    path, text = read("src/test/java/io/rbvm/postgres/PostgresMigratorSelfTest.java")
    text = text.replace("assert migrator.migrate() == 13;", "assert migrator.migrate() == 14;")
    text = text.replace("assert database.checksums.size() == 13;", "assert database.checksums.size() == 14;")
    text = text.replace("assert database.commits == 13;", "assert database.commits == 14;")
    if 'CREATE TABLE rbvm.network_reachability_snapshot' not in text:
        anchor = '''        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_asset_context_evidence"));
'''
        if text.count(anchor) != 1:
            raise RuntimeError("migrator V14 assertion anchor mismatch")
        text = text.replace(anchor, anchor + '''        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_snapshot"));
        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_evidence"));
        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_network_reachability_evidence"));
        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_network_reachability_evidence"));
''', 1)
    if "long networkReachabilitySnapshotCreates" not in text:
        anchor = '''        long assetContextEvidenceCreates = database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.asset_context_evidence")).count();
'''
        if text.count(anchor) != 1:
            raise RuntimeError("migrator V14 count anchor mismatch")
        text = text.replace(anchor, anchor + '''        long networkReachabilitySnapshotCreates = database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_snapshot")).count();
        long networkReachabilityEvidenceCreates = database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_evidence")).count();
''', 1)
    if "== networkReachabilitySnapshotCreates;" not in text:
        anchor = '''        assert database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.asset_context_evidence")).count()
                == assetContextEvidenceCreates;
'''
        if text.count(anchor) != 1:
            raise RuntimeError("migrator V14 replay anchor mismatch")
        text = text.replace(anchor, anchor + '''        assert database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_snapshot")).count()
                == networkReachabilitySnapshotCreates;
        assert database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_evidence")).count()
                == networkReachabilityEvidenceCreates;
''', 1)
    write(path, text)


def finalize_sql_verifier() -> None:
    path, text = read("scripts/verify-sql.py")
    if '(14, "V14__network_reachability_persistence.sql"),' not in text:
        anchor = '            (13, "V13__asset_context_persistence.sql"),\n'
        if text.count(anchor) != 1:
            raise RuntimeError("verify-sql V14 migration anchor mismatch")
        text = text.replace(anchor, anchor + '            (14, "V14__network_reachability_persistence.sql"),\n', 1)
    if "    v14 = migrations[14]\n" not in text:
        anchor = "    v13 = migrations[13]\n"
        if text.count(anchor) != 1:
            raise RuntimeError("verify-sql V14 variable anchor mismatch")
        text = text.replace(anchor, anchor + "    v14 = migrations[14]\n", 1)
    if "V14 is missing network reachability persistence invariant" not in text:
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
            raise RuntimeError("verify-sql V14 block anchor mismatch")
        text = text.replace(marker, block + marker, 1)
    if '"RBVM.NETWORK_REACHABILITY_SNAPSHOT",' not in text:
        anchor = '        "RBVM.FINDING_ASSET_CONTEXT_EVIDENCE",\n'
        if text.count(anchor) != 1:
            raise RuntimeError("verify-sql V14 grant anchor mismatch")
        text = text.replace(anchor, anchor
            + '        "RBVM.NETWORK_REACHABILITY_SNAPSHOT",\n'
            + '        "RBVM.NETWORK_REACHABILITY_EVIDENCE",\n'
            + '        "RBVM.CURRENT_NETWORK_REACHABILITY_EVIDENCE",\n'
            + '        "RBVM.FINDING_NETWORK_REACHABILITY_EVIDENCE",\n', 1)
    # The immutable list has a second occurrence in the same verifier; add only if the revoke marker is absent.
    if "runtime role must keep RBVM.NETWORK_REACHABILITY_SNAPSHOT append-only" not in text:
        marker = '''    for relation in (
        "RBVM.CISA_KEV_CATALOG_SNAPSHOT",
'''
        # Locate the final append-only relation tuple and insert after its Asset Context evidence line.
        pos = text.rfind('        "RBVM.ASSET_CONTEXT_EVIDENCE",\n')
        if pos < 0:
            raise RuntimeError("verify-sql V14 immutable tuple anchor missing")
        end = pos + len('        "RBVM.ASSET_CONTEXT_EVIDENCE",\n')
        text = text[:end] + (
            '        "RBVM.NETWORK_REACHABILITY_SNAPSHOT",\n'
            '        "RBVM.NETWORK_REACHABILITY_EVIDENCE",\n'
        ) + text[end:]
    write(path, text)


def finalize_doc() -> None:
    path, text = read("docs/NETWORK_REACHABILITY_PERSISTENCE.md")
    sentence = "The importer stores `Origin_Label` in the same NFKC + lowercase identity form used by the CSV observation key, so casing or Unicode presentation changes do not fork endpoint streams.\n\n"
    anchor = "Within a persisted snapshot, endpoint identity is:\n\n"
    if sentence not in text:
        if text.count(anchor) != 1:
            raise RuntimeError("persistence doc normalization anchor mismatch")
        text = text.replace(anchor, sentence + anchor, 1)
    write(path, text)


def main() -> None:
    finalize_migrator()
    finalize_runtime_role()
    finalize_importer_normalization()
    finalize_foundation_test()
    finalize_migrator_test()
    finalize_sql_verifier()
    finalize_doc()
    print("V14 reachability finalization applied")


if __name__ == "__main__":
    main()
