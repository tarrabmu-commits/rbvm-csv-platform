#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "db/migration/V28__findings_read_hotpath_indexes.sql"
MIGRATOR = ROOT / "src/main/java/io/rbvm/postgres/PostgresMigrator.java"
READ_CATALOG = ROOT / "src/main/java/io/rbvm/postgres/PostgresReadCatalog.java"
INTEL_SUMMARY = ROOT / "src/main/java/io/rbvm/postgres/PostgresDedicatedIntelligenceSummaryCatalog.java"

migration = MIGRATION.read_text(encoding="utf-8")
migrator = MIGRATOR.read_text(encoding="utf-8")
read_catalog = READ_CATALOG.read_text(encoding="utf-8")
intel_summary = INTEL_SUMMARY.read_text(encoding="utf-8")

required_indexes = [
    "CREATE INDEX exposure_tenant_case_lookup_idx",
    "ON rbvm.exposure (tenant_id, case_id)",
    "CREATE INDEX case_findings_page_order_idx",
    "ON rbvm.vulnerability_case (",
    "CASE current_severity",
    "last_observed_at DESC",
    "public_id",
    "CREATE INDEX observation_tenant_vulnerability_lookup_idx",
    "ON rbvm.observation (tenant_id, vulnerability_id)",
]
for token in required_indexes:
    if token not in migration:
        raise AssertionError(f"Findings hot-path migration missing {token!r}")

if 'new Migration(28, "V28__findings_read_hotpath_indexes.sql")' not in migrator:
    raise AssertionError("PostgresMigrator does not register V28 Findings hot-path migration")

# The row-level exposure count is deliberately preserved. V28 makes its lookup
# bounded by tenant/case instead of allowing one exposure relation scan per row.
for token in [
    "SELECT count(*) FROM rbvm.exposure e",
    "e.tenant_id = c.tenant_id AND e.case_id = c.id",
    "LIMIT ? OFFSET ?",
]:
    if token not in read_catalog:
        raise AssertionError(f"Findings case query contract drifted: missing {token!r}")

match = re.search(
    r"WITH active_vulnerability AS \((.*?)\),\s*cvss AS",
    intel_summary,
    flags=re.DOTALL,
)
if not match:
    raise AssertionError("Could not locate dedicated intelligence active_vulnerability CTE")
active = match.group(1)
if "SELECT DISTINCT o.vulnerability_id AS id" not in active:
    raise AssertionError("Dedicated intelligence summary must preserve every observed CVE")
if "FROM rbvm.observation o" not in active or "o.tenant_id = ?" not in active:
    raise AssertionError("Dedicated intelligence summary is not bounded by tenant-scoped observations")
if "rbvm.vulnerability_case" in active:
    raise AssertionError("Dedicated intelligence summary must not narrow observed CVEs to case rows")

# Performance change only: evidence sources and aggregate interpretation remain unchanged.
for token in [
    "current_cvss_v31_base_evidence",
    "current_epss_evidence",
    "current_cisa_kev_evidence",
    "enriched_vulnerabilities",
    "unenriched_vulnerabilities",
    "stale_vulnerabilities",
    "known_exploited_vulnerabilities",
]:
    if token not in intel_summary:
        raise AssertionError(f"Dedicated intelligence summary semantic output drifted: missing {token!r}")

print("Findings PostgreSQL read hot-path checks: PASS")
