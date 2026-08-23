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
            f"{name}: active execution UI must preserve byte-identical Frontend V2 hosts"
        )
    if re.search(r"[\u0600-\u06ff]", text):
        raise AssertionError(f"{name}: operator UI must remain English-only")

contract = "ACTIVE_RISK_METHOD_EXECUTION_UI_V1"
if host.count(contract) != 1:
    raise AssertionError("Active execution UI contract marker must occur exactly once")
start = host.index(contract)
script_start = host.rfind("<script>", 0, start)
script_end = host.index("</script>", start)
ui = host[script_start:script_end]

doc = (ROOT / "docs/ACTIVE_RISK_METHOD_EXECUTION_UI_V1.md").read_text(encoding="utf-8")
verify_sh = (ROOT / "scripts/verify.sh").read_text(encoding="utf-8")
activation_verifier = (
    ROOT / "scripts/verify-risk-method-selection-policy-activation-ui.py"
).read_text(encoding="utf-8")

required = (
    "EXPLICIT_ACTIVATION_REVISION_EVENT_SHA_AND_DECISION_INPUT_SHA_ONLY_NO_CURRENT_DEFAULT",
    "document.documentElement.dataset.activeRiskMethodExecutionUiContract=CONTRACT",
    "[data-risk-method-policy][aria-selected=\"true\"]",
    "data-active-risk-method-execution-ui",
    "Execute selected risk method",
    "V27 exact historical activation + exact Decision Input V3",
    "This UI never runs the current activation",
    "All execution selectors start empty and remain operator-supplied",
    "No browser state or active-policy lookup pre-fills them",
    "'aria-label':'Exact execution activation revision'",
    "'aria-label':'Exact execution activation event SHA-256'",
    "'aria-label':'Exact execution Decision Input SHA-256'",
    "activationRevision.value=''",
    "activationSha.value=''",
    "inputSha.value=''",
    "Execute exact identities",
    "/api/v1/active-risk-method-executions/${revision}/${eventSha}/${snapshotSha}",
    "{method:'POST'}",
    "Operator role is required to execute an exact active risk method selection",
    "No fallback identity is selected",
    "The UI will not fall back to another policy",
    "No alternate method is selected",
    "Execution requires an exact persisted Decision Input Snapshot V3 identity",
    "failed exact integrity verification",
    "V27 Active Risk Method Execution persistence is unavailable in this runtime",
    "executionStatus==='REPLAYED'",
    "the selected risk method was not re-executed",
    "Read exact execution binding",
    "'aria-label':'Exact execution binding SHA-256 to read'",
    "bindingSha.value=''",
    "/api/v1/active-risk-method-execution-bindings/${sha}",
    "No execution binding matches that exact SHA. No fallback binding is selected",
    "there is no execution or binding collection lookup",
    "binding.activationRevision",
    "binding.activationEventSha256",
    "binding.policyRevision",
    "binding.policySha256",
    "binding.selectionRole",
    "binding.methodFamily",
    "binding.methodId",
    "binding.methodVersion",
    "binding.methodSha256",
    "binding.inputSnapshotSha256",
    "binding.resultFamily",
    "binding.resultSha256",
    "binding.bindingSha256",
    "binding.canonicalPayloadFormat",
    "payload.resultLocation",
    "response?.headers.get('ETag')",
    "response?.headers.get('Location')",
    "Execution provenance does not create Priority, Treatment, SLA, remediation deadline",
)
for needle in required:
    if needle not in ui:
        raise AssertionError(f"Active execution UI missing invariant {needle!r}")

for forbidden in (
    "localStorage",
    "sessionStorage",
    "document.cookie",
    "innerHTML",
    "document.write",
    "Date.now(",
    "new Date()",
    "toISOString()",
    "Math.max",
    "maxRevision",
    "activationRevision+1",
    "activationRevision + 1",
    "latest=true",
    "current=true",
    "defaultPolicy",
    "preferredPolicy",
    "candidates[0]",
    "formulas[0]",
    "methodologies[0]",
    "priorityTier",
    "priorityScore",
    "slaDays",
    "treatmentDecision",
    "remediationDeadline",
    "URLSearchParams",
    "body:",
):
    if forbidden in ui:
        raise AssertionError(
            f"Active execution UI contains forbidden implicit construct {forbidden!r}"
        )

# The execution module must never query activation/resolution control-plane selectors.
for forbidden_path in (
    "/api/v1/risk-method-selection-policy-activation/current",
    "/api/v1/risk-method-selection-policy-activation/current/resolved",
    "/resolved",
):
    if forbidden_path in ui:
        raise AssertionError(
            f"Active execution UI must not resolve execution through {forbidden_path!r}"
        )

# No collection/list calls: only exact POST and exact binding GET are valid API calls here.
if re.search(
    r"api\(\s*['\"]\/api\/v1\/active-risk-method-executions['\"]",
    ui,
):
    raise AssertionError("Active execution UI must not call the execution collection")
if re.search(
    r"api\(\s*['\"]\/api\/v1\/active-risk-method-execution-bindings['\"]",
    ui,
):
    raise AssertionError("Active execution UI must not call the binding collection")
if "/api/v1/active-risk-method-executions?" in ui:
    raise AssertionError("Active execution UI must not query the execution collection")
if "/api/v1/active-risk-method-execution-bindings?" in ui:
    raise AssertionError("Active execution UI must not query the binding collection")

# Execution selectors must be visibly constructed first, then explicitly emptied, then wired to submit.
revision_input = ui.index("'aria-label':'Exact execution activation revision'")
event_input = ui.index("'aria-label':'Exact execution activation event SHA-256'", revision_input)
snapshot_input = ui.index("'aria-label':'Exact execution Decision Input SHA-256'", event_input)
revision_empty = ui.index("activationRevision.value=''", snapshot_input)
event_empty = ui.index("activationSha.value=''", revision_empty)
snapshot_empty = ui.index("inputSha.value=''", event_empty)
execute_handler = ui.index("Execute exact identities", snapshot_empty)
if not (
    revision_input < event_input < snapshot_input < revision_empty
    < event_empty < snapshot_empty < execute_handler
):
    raise AssertionError("Execution identity controls must start explicitly empty before submit")

# Historical binding read must also start empty before its handler is created.
binding_input = ui.index("'aria-label':'Exact execution binding SHA-256 to read'", execute_handler)
binding_empty = ui.index("bindingSha.value=''", binding_input)
read_handler = ui.index("Read exact execution binding", binding_empty)
if not binding_input < binding_empty < read_handler:
    raise AssertionError("Execution binding read must start from an empty exact binding SHA")

# This V1 is additive to the existing Risk Policy Admin/Activation contracts.
for marker in (
    "RISK_METHOD_SELECTION_POLICY_ADMIN_UI_V1",
    "RISK_METHOD_SELECTION_POLICY_ACTIVATION_UI_V1",
    "DERIVED_RISK_METHODOLOGY_COMPARISON_UI_V1",
    "RBVM_FORMULA_V1_PRESENTATION_UI_V1",
    "FINDING_CONTEXT_ASSOCIATION_UI_V1",
):
    if marker not in host:
        raise AssertionError(f"Shared host lost existing UI contract {marker}")

# Activation UI verifier must remain isolated to its own inline script as the host gains modules.
for marker in (
    'start = host.index(contract)',
    'end = host.index("</script>", start)',
    'ui = host[start:end]',
):
    if marker not in activation_verifier:
        raise AssertionError("Activation UI verifier must remain isolated from later UI modules")

normalized_doc = " ".join(doc.split())
for marker in (
    "All three controls start empty",
    "does not derive, remember, copy, or pre-fill them",
    "never exposes a **Run current** action",
    "no query selector and no request body",
    "does not re-execute the risk method",
    "There is no execution collection lookup, binding collection lookup, latest lookup, or fallback lookup",
    "response `ETag` and `Location`",
    "does not calculate, infer, persist, or display a Priority tier, Treatment decision, SLA",
):
    if marker not in normalized_doc:
        raise AssertionError(f"Active execution UI documentation missing {marker!r}")

if 'verify-active-risk-method-execution-ui.py' not in verify_sh:
    raise AssertionError("Active execution UI verifier is not wired into scripts/verify.sh")

print("Active Risk Method Execution UI V1 checks: PASS")
