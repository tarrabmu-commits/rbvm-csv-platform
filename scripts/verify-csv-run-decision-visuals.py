#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src/main/resources/web"
VISUALS = (WEB / "csv-run-visuals.js").read_text(encoding="utf-8")
MOUNT = (WEB / "csv-run-visuals-mount.js").read_text(encoding="utf-8")
CSS = (WEB / "csv-run-visuals.css").read_text(encoding="utf-8")
MOUNT_CSS = (WEB / "csv-run-visuals-mount.css").read_text(encoding="utf-8")
DOC = (ROOT / "docs/RBVM_CSV_RUN_DECISION_VISUALS_V1.md").read_text(encoding="utf-8")
COMPILE = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")
POLICY = (ROOT / "scripts/rank-rbvm-mvp-priority.py").read_text(encoding="utf-8")

SHA = "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388"

required_visuals = [
    "CSV_RUN_DECISION_VISUALS_V1",
    "RBVM_MVP_PRIORITY_POLICY_V1",
    SHA,
    "Pareto priority distribution",
    "Unrankable evidence blockers",
    "Contextual CVSS v4 × EPSS",
    "Pareto dominance landscape",
    "CISA SSVC evidence profile",
    "Customer context matrix",
    "CVSS v4 context modes",
    "CVSS v4 Security Requirements",
    "Organizational Risk method admission",
    "RBVM_MVP_Priority_Status",
    "RBVM_MVP_Priority_Front",
    "RBVM_MVP_Priority_Dominates",
    "RBVM_MVP_Priority_Dominated_By",
    "RBVM_MVP_Priority_Blockers",
    "CISA_Exploitation",
    "CISA_Automatable",
    "CISA_Technical_Impact",
    "Asset_Criticality",
    "Internet_Facing",
    "CVSS4_CR_Resolved",
    "CVSS4_IR_Resolved",
    "CVSS4_AR_Resolved",
    "No CVSS×EPSS multiplication",
    "no SSVC action inference",
]
for token in required_visuals:
    if token not in VISUALS:
        raise AssertionError(f"CSV run visual module missing {token!r}")

for forbidden in [
    "CVSS4_Context_Score *",
    "EPSS_Probability *",
    "cvss * epss",
    "epss * cvss",
    "riskScore",
    "priorityScore",
    "Non-Exploitable",
    "SLA compliance",
    "innerHTML",
    "sessionStorage",
    "localStorage",
]:
    if forbidden.lower() in VISUALS.lower():
        raise AssertionError(f"CSV run visual module contains forbidden construct {forbidden!r}")

required_mount = [
    "CSV_RUN_DECISION_VISUALS_MOUNT_V1",
    "/api/v1/csv-first-priorities/",
    "/api/v1/csv-first-enrichments/",
    "/method-admission",
    "visualRows",
    "EPSS_Probability = 'MISSING'",
    "CVSS4_Context_Score = 'MISSING'",
    "RBVM_MVP_Priority_Dominates = 'MISSING'",
    "RBVM_MVP_Priority_Dominated_By = 'MISSING'",
    "window.rbvmCsvRunVisuals.render",
    "data-csv-run-review",
    "cache: 'no-store'",
]
for token in required_mount:
    if token not in MOUNT:
        raise AssertionError(f"CSV run visual mount missing {token!r}")

for forbidden in [
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "innerHTML",
    "sessionStorage",
    "localStorage",
]:
    if forbidden in MOUNT:
        raise AssertionError(f"CSV run visual mount must remain read-only: found {forbidden!r}")

for token in [
    ".runviz-root",
    ".runviz-grid",
    ".runviz-donut",
    ".runviz-scatter",
    ".runviz-matrix",
    ".runviz-env-stack",
    ".runviz-admission",
    ".runviz-boundary",
    "@media (max-width: 600px)",
    "@media (prefers-reduced-motion: reduce)",
    "@media (forced-colors: active)",
    "@media print",
]:
    if token not in CSS:
        raise AssertionError(f"CSV run visual CSS missing {token!r}")
if ".runviz-loading" not in MOUNT_CSS or "@media print" not in MOUNT_CSS:
    raise AssertionError("CSV run visual mount CSS is incomplete")

for token in [
    "CSV_RUN_DECISION_VISUALS_V1",
    "RBVM_MVP_PRIORITY_POLICY_V1",
    SHA,
    "Pareto priority distribution",
    "Unrankable evidence blockers",
    "Contextual CVSS v4 × EPSS scatter",
    "Pareto dominance landscape",
    "CISA SSVC evidence profile",
    "Customer context matrix",
    "Missing evidence is never visualized as zero",
    "does not",
]:
    if token.lower() not in DOC.lower():
        raise AssertionError(f"CSV run visual documentation missing {token!r}")

js_line = 'cat "$ROOT_DIR/src/main/resources/web/csv-run-visuals.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"'
mount_line = 'cat "$ROOT_DIR/src/main/resources/web/csv-run-visuals-mount.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"'
css_line = 'cat "$ROOT_DIR/src/main/resources/web/csv-run-visuals.css" >> "$MAIN_CLASSES/web/rbvm-ui.css"'
mount_css_line = 'cat "$ROOT_DIR/src/main/resources/web/csv-run-visuals-mount.css" >> "$MAIN_CLASSES/web/rbvm-ui.css"'
for line in [js_line, mount_line, css_line, mount_css_line]:
    if line not in COMPILE:
        raise AssertionError(f"Runtime bundle missing {line!r}")
if COMPILE.index(js_line) > COMPILE.index(mount_line):
    raise AssertionError("CSV run visual renderer must be bundled before its mount layer")

if SHA not in POLICY or '"weights": []' not in POLICY or '"thresholds": []' not in POLICY:
    raise AssertionError("Visualization contract is not pinned to the weight-free, threshold-free MVP policy")

print("CSV run standards-oriented decision visual checks: PASS")
