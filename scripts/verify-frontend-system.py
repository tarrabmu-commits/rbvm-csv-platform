#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src/main/resources/web"
HTML_PAGES = (
    "index.html",
    "cvss-v31.html",
    "cisa-kev.html",
    "epss.html",
    "asset-context.html",
    "network-reachability.html",
    "business-impact.html",
    "assets.html",
    "asset-links.html",
)

CSS_LINK = '<link rel="stylesheet" href="/ui/rbvm-ui.css">'
JS_LINK = '<script src="/ui/rbvm-ui.js" defer></script>'


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def css_rule_body(stylesheet: str, selector: str) -> str:
    match = re.search(rf"(?m)^{re.escape(selector)}\s*\{{([^}}]*)\}}", stylesheet)
    if not match:
        raise AssertionError(f"shared CSS missing rule for {selector!r}")
    return match.group(1)


for page in HTML_PAGES:
    value = text(WEB / page)
    if value.count(CSS_LINK) != 1:
        raise AssertionError(f"{page}: shared CSS link must appear exactly once")
    if value.count(JS_LINK) != 1:
        raise AssertionError(f"{page}: shared JS link must appear exactly once")
    if "<main" not in value:
        raise AssertionError(f"{page}: semantic main landmark is required")
    if 'http://fonts.' in value or 'https://fonts.' in value:
        raise AssertionError(f"{page}: remote font dependency is forbidden")

css = text(WEB / "rbvm-ui.css")
for needle in (
    "--rbvm-control-min: 44px",
    "--rbvm-font-sans: ui-sans-serif, system-ui",
    "--rbvm-page-accent:",
    'html[data-rbvm-page="cvss"]',
    'html[data-rbvm-page="kev"]',
    'html[data-rbvm-page="epss"]',
    'html[data-rbvm-page="context"]',
    'html[data-rbvm-page="reachability"]',
    'html[data-rbvm-page="impact"]',
    'html[data-rbvm-page="assets"]',
    'html[data-rbvm-page="links"]',
    ":focus-visible",
    "@media (prefers-reduced-motion: reduce)",
    "@media (forced-colors: active)",
    "@keyframes rbvm-module-enter",
    ".rbvm-skip-link",
    ".rbvm-shell",
    ".rbvm-nav",
    ".rbvm-mobile-nav",
    ".rbvm-mobile-nav summary",
    ".rbvm-mobile-nav a[aria-current=\"page\"]",
    ".rbvm-page-hero",
    ".rbvm-page-eyebrow",
    ".rbvm-module",
    ".rbvm-metric-card",
    ".rbvm-table-frame",
    ".rbvm-callout",
    ".rbvm-status",
    '[data-rbvm-state="ambiguous"]',
    '[data-rbvm-state="stale"]',
    '[data-rbvm-state="unknown"]',
    "dialog::backdrop",
):
    if needle not in css:
        raise AssertionError(f"shared CSS missing {needle!r}")

if "Inter," in css:
    raise AssertionError("shared frontend typography must remain system-font-only")

for selector in (
    ".rbvm-brand",
    ".rbvm-nav a",
    ".rbvm-icon-button",
    "button, .button-link",
    "input, select, textarea",
):
    if "min-height: var(--rbvm-control-min)" not in css_rule_body(css, selector):
        raise AssertionError(f"{selector}: shared 44px control floor must be applied")

javascript = text(WEB / "rbvm-ui.js")
for needle in (
    "RBVM_FRONTEND_SYSTEM_V1",
    "const PAGE_META = new Map([",
    "dialogOpeners = new WeakMap()",
    "document.documentElement.dataset.rbvmPage = meta.id",
    "document.documentElement.dataset.rbvmPageGroup",
    "aria-current",
    "تجاوز إلى المحتوى الرئيسي",
    "prefers-color-scheme: light",
    "systemTheme.addEventListener('change'",
    "createMobileNav",
    "التنقل الرئيسي للموبايل",
    "disclosure.open ? 'إغلاق قائمة التنقل' : 'فتح قائمة التنقل'",
    "dark ? 'true' : 'false'",
    "skip.href = `#${main.id}`",
    "enhanceHero",
    "rbvm-page-eyebrow",
    "normalizeModules",
    "rbvm-module",
    "rbvm-metric-card",
    "rbvm-table-frame",
    "normalizeTables",
    "rbvm-data-table",
    "normalizeSemanticStates",
    "data.rbvmState",
    "MutationObserver",
    "normalizeDialogs",
    "dialogOpeners.set(dialog, trigger)",
    "dialogOpeners.delete(dialog)",
    "aria-modal",
):
    if needle not in javascript:
        raise AssertionError(f"shared frontend JavaScript missing {needle!r}")

for path, page_id in (
    ("/", "overview"),
    ("/cvss", "cvss"),
    ("/kev", "kev"),
    ("/epss", "epss"),
    ("/asset-context", "context"),
    ("/reachability", "reachability"),
    ("/business-impact", "impact"),
    ("/assets", "assets"),
    ("/asset-links", "links"),
):
    if f"['{path}', {{id: '{page_id}'" not in javascript:
        raise AssertionError(f"shared frontend page identity missing {path} -> {page_id}")

if "trigger.id" in javascript or "rbvmOpenerId" in javascript:
    raise AssertionError("dialog focus restoration must not depend on opener IDs")

# localStorage is allowed only for the non-sensitive theme preference in this shared layer.
if javascript.count("localStorage") != 3 or "rbvm.ui.theme" not in javascript:
    raise AssertionError("shared frontend localStorage use must remain theme-preference-only")

server = text(ROOT / "src/main/java/io/rbvm/csv/CsvPlatformServer.java")
for needle in (
    'loadResource("/web/rbvm-ui.css")',
    'loadResource("/web/rbvm-ui.js")',
    '"/ui/rbvm-ui.css"',
    '"text/css; charset=utf-8"',
    '"/ui/rbvm-ui.js"',
    '"text/javascript; charset=utf-8"',
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
):
    if needle not in server:
        raise AssertionError(f"server frontend wiring missing {needle!r}")

verify = text(ROOT / "scripts/verify.sh")
if "verify-frontend-system.py" not in verify:
    raise AssertionError("verify.sh must invoke the frontend system verifier")

reproducible = text(ROOT / "scripts/verify-reproducible-build.sh")
for needle in (
    "/ui/rbvm-ui.css",
    "/ui/rbvm-ui.js",
    "RBVM_FRONTEND_SYSTEM_V1",
    "Content-Security-Policy",
):
    if needle not in reproducible:
        raise AssertionError(f"packaged frontend smoke missing {needle!r}")

doc = text(ROOT / "docs/FRONTEND_SYSTEM_V1.md")
for needle in (
    "RBVM_FRONTEND_SYSTEM_V1",
    "WCAG 2.2 Level AA",
    "WAI-ARIA",
    "RBVM_POLICY",
    "Modular composition",
    "Page identity",
    "PRESENT|MISSING|UNKNOWN|STALE|AMBIGUOUS",
    "unsafe-inline",
):
    if needle not in doc:
        raise AssertionError(f"frontend contract documentation missing {needle!r}")

print("RBVM frontend system structural checks: PASS")
