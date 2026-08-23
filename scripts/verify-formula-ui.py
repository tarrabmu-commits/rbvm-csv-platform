#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOSTS = [
    "index.html",
    "cvss-v31.html",
    "cisa-kev.html",
    "epss.html",
    "asset-context.html",
    "network-reachability.html",
    "business-impact.html",
    "assets.html",
    "asset-links.html",
]
WEB = ROOT / "src/main/resources/web"
DOC = (ROOT / "docs/FORMULA_UI_V1.md").read_text(encoding="utf-8")
VERIFY = (ROOT / "scripts/verify.sh").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


hosts = {name: (WEB / name).read_text(encoding="utf-8") for name in HOSTS}
canonical = hosts["index.html"]
for name, text in hosts.items():
    require(text == canonical, f"Frontend V2 shared host drifted at {name}")

marker = "const CONTRACT='RBVM_FORMULA_V1_PRESENTATION_UI_V1';"
require(canonical.count(marker) == 1, "Formula UI contract must occur exactly once in shared host")
start = canonical.index(marker)
script_start = canonical.rfind("<script>", 0, start)
script_end = canonical.index("</script>", start)
require(script_start >= 0 and script_end > start, "Formula UI must be contained in one inline script")
formula_ui = canonical[script_start:script_end]

for required in (
    "RBVM_FORMULA_V1_PRESENTATION_UI_V1",
    "EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT",
    "catalog.json?.selectionSemantics!==NO_DEFAULT",
    "api('/api/v1/formulas')",
    "decision-input-snapshots?limit=100",
    "value.contractId==='RBVM_DECISION_INPUT_SNAPSHOT_V3'",
    "snapshotSelect.value=''",
    "formulaSelect.value=''",
    "inputSnapshotSha256:snapshot.snapshotSha256",
    "formulaSha256:formula.formulaSha256",
    "/api/v1/formula-results?${query}",
    "/api/v1/formula-result-materializations/${snapshot.snapshotSha256}",
    "result.resultState==='COMPUTED'",
    "explanation.replayVerified===true",
    "explanation.dimensions||[]",
    "dimension.evidenceReferences||[]",
    "reference.binding",
    "browser never recalculates, reweights, ranks",
    "Absence is not converted into numeric risk",
    "dimensionless RBVM Relative Risk Index",
):
    require(required in formula_ui, f"Formula UI missing invariant {required!r}")

for forbidden in (
    "88bf31f510089b4209b1ffcf1c15b39fef60548209875334f084888316e9028e",
    "formulas[0]",
    "snapshots[0]",
    ".selectedIndex=",
    "latest=true",
    "current=true",
    "defaultFormula",
    "preferredFormula",
    "primaryFormula",
    "localStorage",
    "sessionStorage",
    "document.cookie",
    "parseFloat(",
    "parseInt(",
    ".reduce(",
    "priorityScore",
    "priorityTier",
    "slaDays",
    "treatmentDecision",
    "remediationDeadline",
):
    require(forbidden not in formula_ui, f"Formula UI contains forbidden construct {forbidden!r}")

require("formula.formulaSha256" in formula_ui,
        "Formula UI must consume Formula SHA from catalog response")
require("relativeRiskIndex" in formula_ui,
        "Formula UI must present server-returned Relative Risk Index")
require("relativeRiskIndex" not in formula_ui.split("new URLSearchParams", 1)[0],
        "Formula result must not participate in pre-read browser calculation")

for required in (
    "RBVM_FORMULA_V1_PRESENTATION_UI_V1",
    "GET /api/v1/formulas",
    "EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT",
    "GET /api/v1/formula-results?inputSnapshotSha256={snapshotSha256}&formulaSha256={formulaSha256}",
    "POST /api/v1/formula-result-materializations/{inputSnapshotSha256}",
    "COMPUTED / NOT_APPLICABLE / NON_COMPUTABLE",
    "not hard-coded into browser JavaScript",
    "does not create or infer",
    "localStorage",
    "byte-identical",
):
    require(required.lower() in DOC.lower(), f"Formula UI documentation missing {required!r}")

require('python3 "$ROOT_DIR/scripts/verify-formula-ui.py"' in VERIFY,
        "Formula UI verifier must run in scripts/verify.sh")

print("RBVM Formula V1 browser presentation checks: PASS")
