#!/usr/bin/env python3
"""Structural checks for the dedicated intelligence finding read projection and UI semantics."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "src/main/java/io/rbvm/postgres/PostgresEvidenceAwareCatalog.java"
FACTORY = ROOT / "src/main/java/io/rbvm/postgres/CanonicalProjectionFactory.java"
WEB = ROOT / "src/main/resources/web"
HOSTS = (
    "index.html", "cvss-v31.html", "cisa-kev.html", "epss.html", "asset-context.html",
    "network-reachability.html", "business-impact.html", "assets.html", "asset-links.html",
)

catalog = CATALOG.read_text(encoding="utf-8")
factory = FACTORY.read_text(encoding="utf-8")
ui = (WEB / "rbvm-intelligence-ui.js").read_text(encoding="utf-8")

for needle in (
    "rbvm.current_cvss_v31_base_evidence",
    "rbvm.current_epss_evidence",
    "rbvm.current_cisa_kev_evidence",
    'return count == 0 ? "MISSING" : count == 1 ? "PRESENT" : "AMBIGUOUS"',
    'result.put("kevStatus", kev.isEmpty() ? "UNKNOWN"',
    '"DEDICATED_CURRENT_EVIDENCE_NO_HIDDEN_SOURCE_PRECEDENCE"',
    "new java.io.UncheckedIOException(",
):
    if needle not in catalog:
        raise AssertionError(f"dedicated intelligence catalog missing {needle!r}")

for forbidden in (
    "v.known_exploited",
    "v.epss_probability",
    "v.cvss_base_score",
):
    if forbidden in catalog:
        raise AssertionError(f"dedicated intelligence catalog must not read legacy field {forbidden!r}")

if "installedVersion >= 12" not in factory or "new PostgresEvidenceAwareCatalog(readCatalog, connections)" not in factory:
    raise AssertionError("PostgreSQL V12+ runtime must install the dedicated intelligence read projection")

for needle in (
    "DEDICATED_INTELLIGENCE_PRESENTATION_V1",
    "headers.indexOf('KEV')",
    "kevEvidenceState==='AMBIGUOUS'",
    "kevEvidenceState==='MISSING'",
    "return'UNKNOWN'",
    "no source precedence was applied",
    "function coverage(predicate)",
    "setMetric('Known exploited CVEs',listed)",
    "setMetric('CVSS coverage',`${cvss}%`)",
    "setMetric('EPSS coverage',`${epss}%`)",
    "setMetric('KEV assessed',`${kev}%`)",
    "setMetric('Findings evaluated',byCve.size,'CVEs evaluated')",
):
    if needle not in ui:
        raise AssertionError(f"dedicated intelligence UI missing {needle!r}")

for name in HOSTS:
    host = (WEB / name).read_text(encoding="utf-8")
    marker = '<script src="/ui/rbvm-intelligence-ui.js" defer></script>'
    if host.count(marker) != 1:
        raise AssertionError(f"{name}: dedicated intelligence UI must load exactly once")
    if host.index(marker) > host.index('<script src="/ui/rbvm-ui.js" defer></script>'):
        raise AssertionError(f"{name}: intelligence fetch observer must load before rbvm-ui.js")

print("Dedicated intelligence read checks: PASS")
