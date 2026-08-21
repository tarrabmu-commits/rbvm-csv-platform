#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src/main/resources/web"
HOSTS = ("index.html","cvss-v31.html","cisa-kev.html","epss.html","asset-context.html","network-reachability.html","business-impact.html","assets.html","asset-links.html")
host = (WEB / "index.html").read_text(encoding="utf-8")
for name in HOSTS:
    text = (WEB / name).read_text(encoding="utf-8")
    if text != host:
        raise AssertionError(f"{name}: every legacy UI route must use the same V2 SPA host")
    for needle in ('<html lang="en" dir="ltr">','<main id="rbvm-main" tabindex="-1">','<div id="rbvm-app" aria-live="polite"></div>','<link rel="stylesheet" href="/ui/rbvm-ui.css">','<script src="/ui/rbvm-ui.js" defer></script>','Skip to main content'):
        if needle not in text:
            raise AssertionError(f"{name}: missing {needle!r}")
    if re.search(r"[\u0600-\u06ff]", text):
        raise AssertionError(f"{name}: operator UI host must remain English-only")
    if 'http://fonts.' in text or 'https://fonts.' in text:
        raise AssertionError(f"{name}: remote font dependency is forbidden")

js = (WEB / "rbvm-ui.js").read_text(encoding="utf-8")
css = (WEB / "rbvm-ui.css").read_text(encoding="utf-8")
doc = (ROOT / "docs/FRONTEND_SYSTEM_V2.md").read_text(encoding="utf-8")
for needle in ("RBVM_FRONTEND_SYSTEM_V2","Overview","Findings","Assets","Analytics","Reports","Evidence","Imports","Settings","Decision Readiness","Generate report","Print / Save PDF","Export report data CSV","The current API does not expose historical aggregate snapshots","no hidden RBVM risk score or priority","RBVM will not fabricate trend values","Frontend System V2 contains no in-app sign-in or access-token controls","/api/v1/cases","/api/v1/managed-assets","/api/v1/scanner-assets","/api/v1/cvss-v31-evidence","/api/v1/cisa-kev-evidence","/api/v1/epss-evidence","/api/v1/asset-context-evidence","/api/v1/network-reachability-evidence","/api/v1/business-impact-evidence"):
    if needle not in js:
        raise AssertionError(f"V2 JavaScript missing {needle!r}")
for forbidden in ("sessionStorage","rbvmApiToken","saveToken","apiToken","document.write","innerHTML"):
    if forbidden in js:
        raise AssertionError(f"V2 JavaScript contains forbidden browser/auth construct {forbidden!r}")
if re.search(r"[\u0600-\u06ff]", js):
    raise AssertionError("V2 operator JavaScript must remain English-only")
for needle in ("--rbvm-control-min: 44px","--sidebar-width:","ui-sans-serif, system-ui",".app-shell",".topbar",".sidebar",".nav-link[aria-current=\"page\"]",".metrics",".table-frame",".drawer",".modal",".bar-list",".report-sheet","@media (max-width: 767px)","@media (prefers-reduced-motion: reduce)","@media (forced-colors: active)","@media print",":focus-visible"):
    if needle not in css:
        raise AssertionError(f"V2 CSS missing {needle!r}")
for forbidden in ("linear-gradient(135deg","https://fonts.","http://fonts."):
    if forbidden in css:
        raise AssertionError(f"V2 CSS contains forbidden design dependency {forbidden!r}")
for needle in ("RBVM_FRONTEND_SYSTEM_V2","English","progressive disclosure","recognition","Overview","Findings","Assets","Analytics","Reports","Evidence","Imports","Settings","risk score","historical","browser","accessibility"):
    if needle.lower() not in doc.lower():
        raise AssertionError(f"V2 frontend contract documentation missing {needle!r}")
server = (ROOT / "src/main/java/io/rbvm/csv/CsvPlatformServer.java").read_text(encoding="utf-8")
for needle in ('loadResource("/web/rbvm-ui.css")','loadResource("/web/rbvm-ui.js")','"/ui/rbvm-ui.css"','"/ui/rbvm-ui.js"',"object-src 'none'","frame-ancestors 'none'"):
    if needle not in server:
        raise AssertionError(f"server frontend wiring missing {needle!r}")
print("RBVM Frontend System V2 structural checks: PASS")
