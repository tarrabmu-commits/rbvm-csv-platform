#!/usr/bin/env python3
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
WEB=ROOT/"src/main/resources/web"
HOSTS=("index.html","cvss-v31.html","cisa-kev.html","epss.html","asset-context.html","network-reachability.html","business-impact.html","assets.html","asset-links.html")
for name in HOSTS:
    text=(WEB/name).read_text(encoding="utf-8")
    if '<html lang="en" dir="ltr">' not in text: raise AssertionError(f"{name}: English LTR host is required")
    if text.count('id="rbvm-app"')!=1: raise AssertionError(f"{name}: SPA mount must appear exactly once")
    if re.search(r"[\u0600-\u06ff]",text): raise AssertionError(f"{name}: Arabic copy is not allowed")
js=(WEB/"rbvm-ui.js").read_text(encoding="utf-8")
for needle in ("const CONTRACT = 'RBVM_FRONTEND_SYSTEM_V2'","['/', 'Overview'","'/findings', 'Findings'","'/assets', 'Assets'","'/analytics', 'Analytics'","'/reports', 'Reports'","'/evidence', 'Evidence'","'/imports', 'Imports'","'/settings', 'Settings'","function route()","function routeParams()","function url(path","renderOverview","renderFindings","renderAssets","renderAnalytics","renderReports","renderEvidence","renderImports","renderSettings","aria-current","aria-modal","role:'tablist'","tabIndex = 0","readSetting(THEME_KEY"):
    if needle not in js: raise AssertionError(f"web runtime missing {needle!r}")
for forbidden in ("sessionStorage","rbvmApiToken","saveToken","apiToken","document.write"):
    if forbidden in js: raise AssertionError(f"web runtime contains forbidden legacy pattern {forbidden!r}")
print(f"Web V2 checks: PASS ({len(HOSTS)} SPA hosts)")
