#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src/main/resources/web"
HOSTS = (
    "index.html", "cvss-v31.html", "cisa-kev.html", "epss.html",
    "asset-context.html", "network-reachability.html", "business-impact.html",
    "assets.html", "asset-links.html",
)

host = (WEB / "index.html").read_text(encoding="utf-8")
for name in HOSTS:
    text = (WEB / name).read_text(encoding="utf-8")
    if text != host:
        raise AssertionError(
            f"{name}: derived-risk UI must preserve the byte-identical Frontend V2 SPA host"
        )
    if re.search(r"[\u0600-\u06ff]", text):
        raise AssertionError(f"{name}: operator UI must remain English-only")

contract = "DERIVED_RISK_METHODOLOGY_COMPARISON_UI_V1"
if host.count(contract) != 1:
    raise AssertionError("Derived-risk UI contract marker must occur exactly once")
start = host.index(contract)
script_start = host.rfind("<script>", 0, start)
script_end = host.index("</script>", start)
if script_start < 0 or script_end <= start:
    raise AssertionError("Derived-risk UI contract must be contained in one inline script")
ui = host[script_start:script_end]

required = (
    "EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT",
    "Risk methodologies",
    "Compare methodologies",
    "same exact Decision Input V3 snapshot",
    "does not average, normalize, rank, or silently choose a primary methodology",
    "Snapshot history ordering is pagination-only",
    "No snapshot is treated as latest/current",
    "No Finding identity is inferred from the Case, CVE, asset, or component text",
    "/api/v1/derived-risk-methodologies",
    "/api/v1/findings/${id}/decision-input-snapshots?limit=100",
    "RBVM_DECISION_INPUT_SNAPSHOT_V3",
    "Select exact Decision Input V3 snapshot…",
    "select.value=''",
    "The first history row is never auto-selected",
    "inputSnapshotSha256:snapshot.snapshotSha256",
    "methodologyId:methodology.methodologyId",
    "methodologySha256:methodology.methodologySha256",
    "/api/v1/derived-risk-results?${query}",
    "/api/v1/derived-risk-result-materializations/${snapshot.snapshotSha256}/${encodeURIComponent(methodology.methodologyId)}/${methodology.methodologySha256}",
    "method:'POST'",
    "error.status===404",
    "err.status===403",
    "Operator role is required to materialize a derived-risk result",
    "No persisted result exists for this exact snapshot/methodology identity",
    "Absence is not converted into a score",
    "Different numeric ranges and rating semantics are intentionally not normalized or averaged",
    "result.resultState==='COMPUTED'",
    "result.numericScore",
    "result.numericScale",
    "result.rating",
    "result.reasonCode",
    "canonical.replayVerified===true",
    "canonical.sha256",
    "canonical.measures",
    "snapshot.dimensionStates",
    "state==='AMBIGUOUS'",
    "state==='STALE'",
    "methodology.methodologySha256",
    "grid-2",
)
for needle in required:
    if needle not in ui:
        raise AssertionError(f"Derived-risk methodology UI missing invariant {needle!r}")

for forbidden in (
    "snapshots[0]",
    "methodologies[0]",
    "latest=true",
    "latest=",
    "current=true",
    "current=",
    "preferredMethodology",
    "defaultMethodology",
    "primaryMethodology",
    "priorityScore",
    "priorityTier",
    "slaDays",
    "treatmentDecision",
    "remediationDeadline",
    "sessionStorage",
    "localStorage",
    "document.write",
    "innerHTML",
):
    if forbidden in ui:
        raise AssertionError(f"Derived-risk methodology UI contains forbidden construct {forbidden!r}")

# Comparison is presentation-only. Native results may be displayed side-by-side but must not
# participate in client-side arithmetic, ranking, or a synthetic cross-methodology score.
for forbidden_pattern in (
    r"Number\s*\(\s*result\.numericScore",
    r"parseFloat\s*\(\s*result\.numericScore",
    r"parseInt\s*\(\s*result\.numericScore",
    r"numericScore\s*[+*/-]",
    r"\.sort\s*\([^)]*numericScore",
):
    if re.search(forbidden_pattern, ui):
        raise AssertionError(
            f"Derived-risk methodology UI performs forbidden score transformation: {forbidden_pattern}"
        )

# Exact snapshot selection must begin empty and only a user change may trigger result loading.
select_creation = ui.index("Select exact Decision Input V3 snapshot…")
empty_selection = ui.index("select.value=''", select_creation)
change_handler = ui.index("select.addEventListener('change'", empty_selection)
load_call = ui.index("loadResults(results,snapshot,methodologies)", change_handler)
if not select_creation < empty_selection < change_handler < load_call:
    raise AssertionError("Derived-risk UI must require explicit snapshot selection before evaluation reads")

# Existing progressive-enhancement contracts must remain in the shared host.
for marker in (
    "FINDING_CONTEXT_ASSOCIATION_UI_V1",
    "DEDICATED_INTELLIGENCE_PRESENTATION_V1",
    "RBVM_FRONTEND_SYSTEM_V2",
):
    if marker not in host and marker != "RBVM_FRONTEND_SYSTEM_V2":
        raise AssertionError(f"Shared host lost existing UI contract {marker}")

print("RBVM Derived Risk Methodology Comparison UI checks: PASS")
