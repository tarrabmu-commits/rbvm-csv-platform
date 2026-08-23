#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src/main/resources/web"
JS = (WEB / "rbvm-dashboard-v4.js").read_text(encoding="utf-8")
CSS = (WEB / "rbvm-dashboard-v4.css").read_text(encoding="utf-8")
DOC = (ROOT / "docs/RBVM_DASHBOARD_V4.md").read_text(encoding="utf-8")
COMPILE = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")

required_js = [
    "RBVM_DASHBOARD_V4_STANDARDS_VIEW",
    "Vulnerability decision dashboard",
    "Technical severity",
    "Confirmed exploitation",
    "CVSS × EPSS decision landscape",
    "Severity × confirmed exploitation",
    "Highest EPSS probabilities",
    "Most affected assets",
    "Finding age distribution",
    "Asset criticality",
    "Decision readiness",
    "Treatment priority",
    "Historical response trend",
    "EPSS probability · next 30 days",
    "CISA KEV listed",
    "No canonical priority field exposed here",
    "Historical aggregation API required",
    "/api/v1/catalog/summary",
    "/api/v1/cases?",
    "/api/v1/managed-assets?",
]
for token in required_js:
    if token not in JS:
        raise AssertionError(f"Dashboard V4 JavaScript missing {token!r}")

for forbidden in [
    "CVSS * EPSS",
    "cvssBaseScore *",
    "epssProbability *",
    "Non-Exploitable",
    "riskScore",
    "priorityScore",
    "SLA Compliance",
    "innerHTML",
    "sessionStorage",
]:
    if forbidden in JS:
        raise AssertionError(f"Dashboard V4 contains forbidden construct {forbidden!r}")

for token in [
    ".v4-kpis",
    ".v4-grid",
    ".v4-donut",
    ".v4-readiness",
    ".v4-scatter",
    ".v4-heatmap",
    ".v4-bars",
    "@media (max-width:767px)",
    "@media (forced-colors:active)",
    "@media (prefers-reduced-motion:reduce)",
    "@media print",
]:
    if token not in CSS:
        raise AssertionError(f"Dashboard V4 CSS missing {token!r}")

for token in [
    "NIST CSF 2.0",
    "NIST IR 8286",
    "NIST IR 8286D",
    "NIST SP 800-40",
    "CISA KEV",
    "CISA SSVC",
    "FIRST CVSS",
    "FIRST EPSS",
    "Organizational Risk",
    "current-state survivors",
]:
    if token.lower() not in DOC.lower():
        raise AssertionError(f"Dashboard V4 documentation missing {token!r}")

for token in [
    'cat "$ROOT_DIR/src/main/resources/web/rbvm-dashboard-v4.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"',
    'cat "$ROOT_DIR/src/main/resources/web/rbvm-dashboard-v4.css" >> "$MAIN_CLASSES/web/rbvm-ui.css"',
]:
    if token not in COMPILE:
        raise AssertionError("Dashboard V4 runtime bundle wiring is missing")

print("RBVM Dashboard V4 standards-oriented visual checks: PASS")
