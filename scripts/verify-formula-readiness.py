#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
atlas = (ROOT / "docs/GLOBAL_RBVM_FORMULA_ATLAS_V1.md").read_text(encoding="utf-8")
readiness = (ROOT / "docs/RBVM_FORMULA_READINESS_V1.md").read_text(encoding="utf-8")
readme = (ROOT / "README.md").read_text(encoding="utf-8")

for needle in (
    "GLOBAL_RBVM_FORMULA_ATLAS_V1",
    "NIST SP 800-30 Rev. 1",
    "NIST IR 8286D Update 1",
    "FIRST CVSS",
    "FIRST EPSS",
    "CISA Known Exploited Vulnerabilities",
    "CERT/SEI SSVC 2.0",
    "OWASP Risk Rating Methodology",
    "MITRE CWSS 1.0",
    "Open FAIR",
    "Tenable",
    "Qualys TruRisk",
    "Rapid7 Active Risk",
    "does not authorize",
    "do not copy",
    "Risk Result",
    "Priority",
    "SLA",
):
    if needle.lower() not in atlas.lower():
        raise AssertionError(f"formula atlas missing required concept {needle!r}")

for url in (
    "https://csrc.nist.gov/pubs/sp/800/30/r1/final",
    "https://csrc.nist.gov/pubs/ir/8286/d/upd1/final",
    "https://www.first.org/cvss/",
    "https://www.first.org/epss/",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "https://insights.sei.cmu.edu/library/prioritizing-vulnerability-response-a-stakeholder-specific-vulnerability-categorization-version-20/",
    "https://owasp.org/www-community/OWASP_Risk_Rating_Methodology",
    "https://cwe.mitre.org/cwss/cwss_v1.0.html",
    "https://www.opengroup.org/open-fair",
):
    if url not in atlas:
        raise AssertionError(f"formula atlas missing official source {url!r}")

for needle in (
    "RBVM_FORMULA_READINESS_V1",
    "hard blocker",
    "one canonical Finding",
    "immutable Decision Input Snapshot",
    "Applicability",
    "CVSS",
    "CISA KEV",
    "EPSS",
    "Asset Context",
    "Reachability",
    "Business / Mission Impact",
    "PRESENT",
    "MISSING",
    "STALE",
    "AMBIGUOUS",
    "compensating controls",
    "formulaId",
    "formulaVersion",
    "canonicalRepresentation",
    "sha256",
    "Risk Result",
    "Golden-case suite",
    "Priority / Treatment / SLA",
    "remains intentionally unimplemented",
):
    if needle.lower() not in readiness.lower():
        raise AssertionError(f"formula readiness contract missing {needle!r}")

for forbidden in (
    "missing => 0",
    "stale => latest current row",
    "ambiguous => highest numeric value",
    "missing epss => probability 0",
    "missing business impact => low",
):
    # Forbidden constructs must appear only as explicitly documented examples of what must not happen.
    if forbidden.lower() not in readiness.lower():
        raise AssertionError(f"formula readiness must explicitly forbid {forbidden!r}")

for required_readme in (
    "Formula Readiness / Formula Contract research",
    "not with arbitrary scoring",
):
    if required_readme.lower() not in readme.lower():
        raise AssertionError(f"README roadmap missing formula-readiness boundary {required_readme!r}")

if "RBVM_FORMULA_V1 =" in readiness or "Risk Score =" in readiness:
    raise AssertionError("formula readiness document must not define a scoring equation")

print("RBVM formula atlas/readiness structural checks: PASS")
