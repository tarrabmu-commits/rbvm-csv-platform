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
            f"{name}: risk-method policy UI must preserve byte-identical Frontend V2 hosts"
        )
    if re.search(r"[\u0600-\u06ff]", text):
        raise AssertionError(f"{name}: operator UI must remain English-only")

contract = "RISK_METHOD_SELECTION_POLICY_ADMIN_UI_V1"
if host.count(contract) != 1:
    raise AssertionError("Risk Method Selection Policy UI contract marker must occur exactly once")
start = host.index(contract)
end = host.index('<script src="/ui/rbvm-ui.js" defer></script>', start)
ui = host[start:end]

required = (
    "EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT",
    "EXACT_REVISION_AND_SHA_NO_CURRENT_LATEST_OR_DEFAULT",
    "Risk policy",
    "Risk Method Selection Policy administration is tenant-scoped",
    "does not infer an active, current, latest, or default revision",
    "Candidate catalog order is presentation-only",
    "never averaged or ranked here",
    "/api/v1/formulas",
    "/api/v1/derived-risk-methodologies",
    "family:'RBVM_FORMULA'",
    "family:'STANDARD_DERIVED'",
    "Select exact risk method identity…",
    "methodSelect.value=''",
    "revision.value=''",
    "readRevision.value=''",
    "readSha.value=''",
    "No value is derived from existing revisions or catalog order",
    "/api/v1/risk-method-selection-policy-installations/${exact}/${candidate.family}/${encodeURIComponent(candidate.id)}/${candidate.version}/${candidate.sha}",
    "{method:'POST'}",
    "Operator role is required to install a risk-method policy revision",
    "the UI will not auto-increment it",
    "/api/v1/risk-method-selection-policies/${exact}/${sha}",
    "No fallback revision is selected",
    "payload?.selectionSemantics!==POLICY_SEMANTICS",
    "response.headers.get('ETag')",
    "response.headers.get('Location')",
    "activation requires a separate versioned contract",
    "there is no collection, max-revision, current, latest, or default lookup",
    "Order carries no precedence, preference, or default semantics",
)
for needle in required:
    if needle not in ui:
        raise AssertionError(f"Risk Method Selection Policy UI missing invariant {needle!r}")

for forbidden in (
    "localStorage",
    "sessionStorage",
    "innerHTML",
    "document.write",
    "latest=true",
    "current=true",
    "latest=",
    "current=",
    "maxRevision",
    "Math.max",
    "revision+1",
    "revision + 1",
    "candidates[0]",
    "formulas[0]",
    "methodologies[0]",
    "selectedIndex=0",
    "selectedIndex = 0",
    "activePolicy",
    "currentPolicy",
    "defaultPolicy",
    "preferredPolicy",
    "priorityTier",
    "priorityScore",
    "slaDays",
    "treatmentDecision",
    "remediationDeadline",
):
    if forbidden in ui:
        raise AssertionError(
            f"Risk Method Selection Policy UI contains forbidden implicit construct {forbidden!r}"
        )

# The exact policy collection itself must never be fetched; only exact revision+SHA reads are valid.
if re.search(r"api\(\s*['\"]\/api\/v1\/risk-method-selection-policies['\"]", ui):
    raise AssertionError("Risk Method Selection Policy UI must not list policy revisions")
if "/api/v1/risk-method-selection-policies?" in ui:
    raise AssertionError("Risk Method Selection Policy UI must not query a policy collection")

# Both installation selectors begin empty after their options/attributes are created.
method_option = ui.index("Select exact risk method identity…")
method_empty = ui.index("methodSelect.value=''", method_option)
revision_input = ui.index("'aria-label':'Policy revision'", method_empty)
revision_empty = ui.index("revision.value=''", revision_input)
install_handler = ui.index("Install exact policy revision", revision_empty)
if not method_option < method_empty < revision_input < revision_empty < install_handler:
    raise AssertionError("Policy installation must start with explicit empty method and revision selectors")

# Exact historical read also begins empty and requires both immutable identifiers.
read_revision = ui.index("'aria-label':'Exact policy revision to read'", install_handler)
read_revision_empty = ui.index("readRevision.value=''", read_revision)
read_sha = ui.index("'aria-label':'Exact policy SHA-256 to read'", read_revision_empty)
read_sha_empty = ui.index("readSha.value=''", read_sha)
read_handler = ui.index("Read exact policy revision", read_sha_empty)
if not read_revision < read_revision_empty < read_sha < read_sha_empty < read_handler:
    raise AssertionError("Exact policy read must start with empty revision and SHA inputs")

for marker in (
    "DERIVED_RISK_METHODOLOGY_COMPARISON_UI_V1",
    "RBVM_FORMULA_V1_PRESENTATION_UI_V1",
    "FINDING_CONTEXT_ASSOCIATION_UI_V1",
    "DEDICATED_INTELLIGENCE_PRESENTATION_V1",
):
    if marker not in host:
        raise AssertionError(f"Shared host lost existing UI contract {marker}")

print("Risk Method Selection Policy Administration UI checks: PASS")
