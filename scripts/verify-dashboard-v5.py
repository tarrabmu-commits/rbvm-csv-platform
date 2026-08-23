#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src/main/resources/web"
JS = (WEB / "rbvm-dashboard-v5.js").read_text(encoding="utf-8")
CSS = (WEB / "rbvm-dashboard-v5.css").read_text(encoding="utf-8")
DOC = (ROOT / "docs/RBVM_DASHBOARD_V5.md").read_text(encoding="utf-8")
INTEL = (ROOT / "src/main/java/io/rbvm/csv/VulnerabilityIntelligenceEvidence.java").read_text(encoding="utf-8")
SUMMARY = (ROOT / "src/main/java/io/rbvm/domain/VulnerabilityIntelligenceSummary.java").read_text(encoding="utf-8")
COMPILE = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")

for token in [
    "RBVM_DASHBOARD_V5_LIFECYCLE_VIEW",
    "Current workflow state",
    "First-observed cohorts",
    "Intelligence freshness",
    "CISA KEV due-date reference",
    "Semantic guardrail",
    "SOURCE_RESOLVED",
    "ACCEPTED_RISK",
    "FALSE_POSITIVE",
    "CLOSED_MANUAL",
    "detection cadence",
    "not a customer SLA",
    "priorityDistributionDeprecated",
]:
    if token not in JS:
        raise AssertionError(f"Dashboard V5 JavaScript missing {token!r}")

for forbidden in [
    "Remediation rate",
    "SLA compliance",
    "CVSS * EPSS",
    "cvssBaseScore *",
    "epssProbability *",
    "riskScore",
    "priorityScore",
    "Non-Exploitable",
    "innerHTML",
    "sessionStorage",
]:
    if forbidden in JS:
        raise AssertionError(f"Dashboard V5 contains forbidden or misleading construct {forbidden!r}")

for token in [
    ".v5-donut-wrap",
    ".v5-cohort-chart",
    ".v5-reference-row",
    ".v5-semantic-guardrail",
    "@media (max-width: 767px)",
    "@media (prefers-reduced-motion: reduce)",
    "@media (forced-colors: active)",
    "@media print",
]:
    if token not in CSS:
        raise AssertionError(f"Dashboard V5 CSS missing {token!r}")

for token in [
    'LEGACY_V2_INTELLIGENCE_PRIORITY_HEURISTIC_V1',
    'LEGACY_REFERENCE_ONLY_NOT_RBVM_MVP_PRIORITY_OR_ORGANIZATIONAL_RISK',
    'legacyHeuristicTier()',
    'Compatibility accessor; API consumers must inspect priorityTierSemantics.',
    'output.put("priorityTierDeprecated", true)',
    'output.put("priorityTierSemantics", LEGACY_HEURISTIC_SEMANTICS)',
]:
    if token not in INTEL:
        raise AssertionError(f"Vulnerability intelligence guardrail missing {token!r}")

for token in [
    'priorityDistributionDeprecated',
    'priorityDistributionSemantics',
    'legacyHeuristicPriorityDistribution',
    'legacyHeuristicId',
]:
    if token not in SUMMARY:
        raise AssertionError(f"Vulnerability intelligence summary guardrail missing {token!r}")

for token in [
    'RBVM_DASHBOARD_V5_LIFECYCLE_VIEW',
    'SOURCE_RESOLVED',
    'First-observed cohorts',
    'CISA KEV due-date reference',
    'LEGACY_REFERENCE_ONLY_NOT_RBVM_MVP_PRIORITY_OR_ORGANIZATIONAL_RISK',
    'does **not**',
]:
    if token.lower() not in DOC.lower():
        raise AssertionError(f"Dashboard V5 documentation missing {token!r}")

if 'cat "$ROOT_DIR/src/main/resources/web/rbvm-dashboard-v5.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"' not in COMPILE:
    raise AssertionError("Dashboard V5 JavaScript is not bundled into runtime rbvm-ui.js")
if 'cat "$ROOT_DIR/src/main/resources/web/rbvm-dashboard-v5.css" >> "$MAIN_CLASSES/web/rbvm-ui.css"' not in COMPILE:
    raise AssertionError("Dashboard V5 CSS is not bundled into runtime rbvm-ui.css")

print("RBVM Dashboard V5 lifecycle and semantic checks: PASS")
