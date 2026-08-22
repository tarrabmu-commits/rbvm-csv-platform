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
        raise AssertionError(f"{name}: Finding-context UI must preserve the shared Frontend V2 SPA host")
    if re.search(r"[\u0600-\u06ff]", text):
        raise AssertionError(f"{name}: operator UI must remain English-only")

start = host.index("FINDING_CONTEXT_ASSOCIATION_UI_V1")
end = host.index('<script src="/ui/rbvm-ui.js" defer></script>')
ui = host[start:end]

required = (
    "FINDING_CONTEXT_ASSOCIATION_UI_V1",
    "x.findingId",
    "Component-specific Finding",
    "Candidate evidence and association state are separate",
    "never auto-links a target or service",
    "NEVER_ASSESSED",
    "Not assessed",
    "Unlinked",
    "/api/v1/network-reachability-evidence?limit=500&asset=",
    "/api/v1/business-impact-evidence?limit=500&asset=",
    "sourceProfile=",
    "/api/v1/findings/${id}/reachability-links?limit=500",
    "/api/v1/findings/${id}/business-service-links?limit=500",
    "/api/v1/findings/${id}/reachability-links/current",
    "/api/v1/findings/${id}/business-service-links/current",
    "/api/v1/findings/${id}/reachability-links/revisions?",
    "/api/v1/findings/${id}/business-service-links/revisions?",
    "Immutable history",
    "No prior decision",
    "This exact target has never been assessed",
    "originScope:v.originScope",
    "originLabel:v.originLabel",
    "transportProtocol:v.transportProtocol",
    "targetPort:v.targetPort??null",
    "businessService:v",
    "'If-Match'",
    "r.headers.get('ETag')",
    "x.status===412",
    "identical retry is not assumed to create a new audit event",
    "No identifier is inferred from CVE, asset name, or component text",
)
for needle in required:
    if needle not in ui:
        raise AssertionError(f"Finding-context UI missing {needle!r}")

for forbidden in (
    "detail.caseId",
    "/api/v1/findings/${detail.",
    "AUTO_LINK",
    "INFERRED_LINK",
    "riskScore",
    "priorityScore",
    "innerHTML",
    "localStorage",
    "sessionStorage",
    "document.write",
):
    if forbidden in ui:
        raise AssertionError(f"Finding-context UI contains forbidden construct {forbidden!r}")

if "while(tabs.nextSibling)tabs.nextSibling.remove()" not in ui:
    raise AssertionError("Context tab must render inside the exact Finding drawer without creating a parallel Case route")

print("Finding context association UI checks: PASS")
