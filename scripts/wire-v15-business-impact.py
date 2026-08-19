#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def require_once(text, anchor, label):
    if text.count(anchor) != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {text.count(anchor)}")


def migrator():
    p = ROOT / "src/main/java/io/rbvm/postgres/PostgresMigrator.java"
    s = p.read_text()
    old = '            new Migration(14, "V14__network_reachability_persistence.sql")\n'
    new = ('            new Migration(14, "V14__network_reachability_persistence.sql"),\n'
           '            new Migration(15, "V15__business_impact_persistence.sql")\n')
    require_once(s, old, "migrator V15")
    p.write_text(s.replace(old, new, 1))


def runtime_role():
    p = ROOT / "db/security/runtime-role.sql"
    s = p.read_text()
    old = "    rbvm.network_reachability_snapshot,\n    rbvm.network_reachability_evidence\nTO rbvm_runtime;\n"
    new = "    rbvm.network_reachability_snapshot,\n    rbvm.network_reachability_evidence,\n    rbvm.business_impact_snapshot,\n    rbvm.business_impact_evidence\nTO rbvm_runtime;\n"
    require_once(s, old, "runtime history grant")
    s = s.replace(old, new, 1)
    old = "    rbvm.current_network_reachability_evidence,\n    rbvm.finding_network_reachability_evidence\nTO rbvm_runtime;\n"
    new = "    rbvm.current_network_reachability_evidence,\n    rbvm.finding_network_reachability_evidence,\n    rbvm.current_business_impact_evidence,\n    rbvm.finding_business_impact_evidence\nTO rbvm_runtime;\n"
    require_once(s, old, "runtime view grant")
    s = s.replace(old, new, 1)
    anchor = "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.network_reachability_evidence FROM rbvm_runtime;\n"
    require_once(s, anchor, "runtime append-only revoke")
    s = s.replace(anchor, anchor
        + "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.business_impact_snapshot FROM rbvm_runtime;\n"
        + "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.business_impact_evidence FROM rbvm_runtime;\n", 1)
    p.write_text(s)


def foundation():
    p = ROOT / "src/test/java/io/rbvm/postgres/PostgresFoundationSelfTest.java"
    s = p.read_text()
    old = '            "/db/migration/V14__network_reachability_persistence.sql"\n'
    new = ('            "/db/migration/V14__network_reachability_persistence.sql",\n'
           '            "/db/migration/V15__business_impact_persistence.sql"\n')
    require_once(s, old, "foundation resource")
    s = s.replace(old, new, 1)
    anchor = "        networkReachabilityPersistencePreservesEvidenceSemantics();\n"
    require_once(s, anchor, "foundation semantic call")
    s = s.replace(anchor, anchor + "        businessImpactPersistencePreservesEvidenceSemantics();\n", 1)
    anchor = "        PostgresNetworkReachabilityImporterSelfTest.main(args);\n"
    require_once(s, anchor, "foundation importer call")
    s = s.replace(anchor, anchor + "        PostgresBusinessImpactImporterSelfTest.main(args);\n", 1)
    marker = "    private static String resource(String name) throws Exception {\n"
    require_once(s, marker, "foundation method insertion")
    method = '''    private static void businessImpactPersistencePreservesEvidenceSemantics() throws Exception {
        String script = resource("/db/migration/V15__business_impact_persistence.sql");
        assert script.contains("CREATE TABLE rbvm.business_impact_snapshot");
        assert script.contains("CREATE TABLE rbvm.business_impact_evidence");
        assert script.contains("UNIQUE (tenant_id, impact_source, observed_at)");
        assert script.contains("business_service_normalized");
        assert script.contains("impact_level IN ('SEVERE', 'HIGH', 'MODERATE', 'LOW', 'NEGLIGIBLE', 'UNKNOWN')");
        assert script.contains("REFERENCES rbvm.asset(tenant_id, id)");
        assert script.contains("REFERENCES rbvm.business_impact_snapshot(tenant_id, id)");
        assert script.contains("CREATE VIEW rbvm.current_business_impact_evidence");
        assert script.contains("CREATE VIEW rbvm.finding_business_impact_evidence");
        assert script.contains("s.impact_source");
        assert script.contains("s.observed_at DESC");
        assert script.contains("(i.id IS NOT NULL) AS business_impact_observed");
        assert script.contains("never fabricated as LOW, NEGLIGIBLE, or UNKNOWN");
        assert !script.contains("impact_weight");
        assert !script.contains("risk_score");
        assert !script.contains("priority_tier");
        assert !script.contains("sla_days");
        assert !script.contains("cvss_base_score");
        assert !script.contains("epss_probability");
        assert !script.contains("known_exploited");
        assert !script.contains("internet_exposed");
    }

'''
    s = s.replace(marker, method + marker, 1)
    p.write_text(s)


def migrator_test():
    p = ROOT / "src/test/java/io/rbvm/postgres/PostgresMigratorSelfTest.java"
    s = p.read_text()
    s = s.replace("assert migrator.migrate() == 14;", "assert migrator.migrate() == 15;")
    s = s.replace("assert database.checksums.size() == 14;", "assert database.checksums.size() == 15;")
    s = s.replace("assert database.commits == 14;", "assert database.commits == 15;")
    anchor = '''        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_network_reachability_evidence"));
'''
    require_once(s, anchor, "migrator V15 create assertions")
    s = s.replace(anchor, anchor + '''        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE TABLE rbvm.business_impact_snapshot"));
        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE TABLE rbvm.business_impact_evidence"));
        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE VIEW rbvm.current_business_impact_evidence"));
        assert database.executedSql.stream()
                .anyMatch(sql -> sql.contains("CREATE VIEW rbvm.finding_business_impact_evidence"));
''', 1)
    anchor = '''        long networkReachabilityEvidenceCreates = database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_evidence")).count();
'''
    require_once(s, anchor, "migrator V15 count")
    s = s.replace(anchor, anchor + '''        long businessImpactSnapshotCreates = database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.business_impact_snapshot")).count();
        long businessImpactEvidenceCreates = database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.business_impact_evidence")).count();
''', 1)
    anchor = '''        assert database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.network_reachability_evidence")).count()
                == networkReachabilityEvidenceCreates;
'''
    require_once(s, anchor, "migrator V15 replay")
    s = s.replace(anchor, anchor + '''        assert database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.business_impact_snapshot")).count()
                == businessImpactSnapshotCreates;
        assert database.executedSql.stream()
                .filter(sql -> sql.contains("CREATE TABLE rbvm.business_impact_evidence")).count()
                == businessImpactEvidenceCreates;
''', 1)
    p.write_text(s)


def sql_verifier():
    p = ROOT / "scripts/verify-sql.py"
    s = p.read_text()
    anchor = '            (14, "V14__network_reachability_persistence.sql"),\n'
    require_once(s, anchor, "verify-sql migration")
    s = s.replace(anchor, anchor + '            (15, "V15__business_impact_persistence.sql"),\n', 1)
    anchor = "    v14 = migrations[14]\n"
    require_once(s, anchor, "verify-sql v15 variable")
    s = s.replace(anchor, anchor + "    v15 = migrations[15]\n", 1)
    marker = "    runtime_role = \" \".join(\n"
    require_once(s, marker, "verify-sql invariant marker")
    block = '''    for invariant in (
        "CREATE TABLE RBVM.BUSINESS_IMPACT_SNAPSHOT",
        "CREATE TABLE RBVM.BUSINESS_IMPACT_EVIDENCE",
        "UNIQUE (TENANT_ID, IMPACT_SOURCE, OBSERVED_AT)",
        "BUSINESS_SERVICE_NORMALIZED",
        "IMPACT_LEVEL IN ('SEVERE', 'HIGH', 'MODERATE', 'LOW', 'NEGLIGIBLE', 'UNKNOWN')",
        "REFERENCES RBVM.ASSET(TENANT_ID, ID)",
        "REFERENCES RBVM.BUSINESS_IMPACT_SNAPSHOT(TENANT_ID, ID)",
        "CREATE VIEW RBVM.CURRENT_BUSINESS_IMPACT_EVIDENCE",
        "CREATE VIEW RBVM.FINDING_BUSINESS_IMPACT_EVIDENCE",
        "S.IMPACT_SOURCE",
        "S.OBSERVED_AT DESC",
        "(I.ID IS NOT NULL) AS BUSINESS_IMPACT_OBSERVED",
    ):
        if invariant not in v15:
            raise AssertionError(f"V15 is missing Business Impact persistence invariant {invariant}")
    for forbidden in (
        "IMPACT_WEIGHT", "RISK_SCORE", "PRIORITY_TIER", "SLA_DAYS", "CVSS_BASE_SCORE",
        "EPSS_PROBABILITY", "KNOWN_EXPLOITED", "INTERNET_EXPOSED"
    ):
        if forbidden in v15:
            raise AssertionError(f"V15 must not derive {forbidden}")

'''
    s = s.replace(marker, block + marker, 1)
    anchor = '        "RBVM.FINDING_NETWORK_REACHABILITY_EVIDENCE",\n'
    require_once(s, anchor, "verify-sql grant list")
    s = s.replace(anchor, anchor
        + '        "RBVM.BUSINESS_IMPACT_SNAPSHOT",\n'
        + '        "RBVM.BUSINESS_IMPACT_EVIDENCE",\n'
        + '        "RBVM.CURRENT_BUSINESS_IMPACT_EVIDENCE",\n'
        + '        "RBVM.FINDING_BUSINESS_IMPACT_EVIDENCE",\n', 1)
    # append-only relation list is the last occurrence of network reachability evidence
    token = '        "RBVM.NETWORK_REACHABILITY_EVIDENCE",\n'
    pos = s.rfind(token)
    if pos < 0:
        raise RuntimeError("verify-sql append-only anchor missing")
    end = pos + len(token)
    s = s[:end] + ('        "RBVM.BUSINESS_IMPACT_SNAPSHOT",\n'
                    '        "RBVM.BUSINESS_IMPACT_EVIDENCE",\n') + s[end:]
    p.write_text(s)


def main():
    migrator(); runtime_role(); foundation(); migrator_test(); sql_verifier()
    print("V15 Business Impact wiring applied")


if __name__ == "__main__":
    main()
