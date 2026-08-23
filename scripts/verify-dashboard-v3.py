#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src/main/resources/web"
JS = (WEB / "rbvm-dashboard.js").read_text(encoding="utf-8")
CSS = (WEB / "rbvm-dashboard.css").read_text(encoding="utf-8")
COMPILE = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")
DOC = (ROOT / "docs/RBVM_DASHBOARD_V3.md").read_text(encoding="utf-8")

required_js = [
    "RBVM_DASHBOARD_V3",
    "/api/v1/catalog/summary",
    "/api/v1/cases?",
    "/api/v1/managed-assets?",
    "Current findings",
    "Unique CVEs",
    "Exposure instances",
    "Affected assets",
    "Known exploited",
    "Mission critical assets",
    "Current exposure by severity",
    "Known exploited signal",
    "Most affected assets",
    "Critical/High + KEV concentration",
    "Finding age distribution",
    "Managed asset criticality",
    "Evidence coverage",
    "Operational trend",
    "Historical aggregation required",
    "knownExploited === true",
    "Not listed / not established",
    "No SLA compliance is shown",
    "No CVSS × EPSS multiplication",
]
for token in required_js:
    if token not in JS:
        raise AssertionError(f"Dashboard V3 JavaScript missing {token!r}")

for forbidden in [
    "Non-Exploitable",
    "Exploitable vs Non-Exploitable",
    "riskScore",
    "priorityScore",
    "remediationSla",
    "SLA Compliance by Severity",
    "CVSS4_Context_Score *",
    "EPSS_Probability *",
    "innerHTML",
    "sessionStorage",
]:
    if forbidden in JS:
        raise AssertionError(f"Dashboard V3 contains forbidden or misleading construct {forbidden!r}")

for token in [
    ".dashboard-root",
    ".dashboard-kpis",
    ".dashboard-grid",
    ".dashboard-card",
    ".dashboard-bars",
    ".dashboard-split-meter",
    ".dashboard-coverage",
    "@media (max-width: 767px)",
    "@media (forced-colors: active)",
    "@media print",
]:
    if token not in CSS:
        raise AssertionError(f"Dashboard V3 CSS missing {token!r}")

if 'cat "$ROOT_DIR/src/main/resources/web/rbvm-dashboard.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"' not in COMPILE:
    raise AssertionError("Dashboard V3 JavaScript is not bundled into runtime rbvm-ui.js")
if 'cat "$ROOT_DIR/src/main/resources/web/rbvm-dashboard.css" >> "$MAIN_CLASSES/web/rbvm-ui.css"' not in COMPILE:
    raise AssertionError("Dashboard V3 CSS is not bundled into runtime rbvm-ui.css")

for token in [
    "RBVM_DASHBOARD_V3",
    "VA dashboard",
    "CISA KEV",
    "Asset Criticality",
    "historical",
    "SLA",
    "Organizational Risk",
    "CVSS × EPSS",
]:
    if token.lower() not in DOC.lower():
        raise AssertionError(f"Dashboard V3 documentation missing {token!r}")

print("RBVM Dashboard V3 structural and semantics checks: PASS")
