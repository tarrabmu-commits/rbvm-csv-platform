#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
compile_sh = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")
core = (ROOT / "src/main/resources/web/rbvm-dashboard-core.js").read_text(encoding="utf-8")
doc = (ROOT / "docs/RBVM_STABILIZATION_V1.md").read_text(encoding="utf-8")

for forbidden in [
    'cat "$ROOT_DIR/src/main/resources/web/rbvm-dashboard.js"',
    'cat "$ROOT_DIR/src/main/resources/web/rbvm-dashboard-v4.js"',
    'cat "$ROOT_DIR/src/main/resources/web/rbvm-dashboard-v5.js"',
]:
    if forbidden in compile_sh:
        raise AssertionError(f"legacy dashboard overlay still bundled: {forbidden}")

for required in [
    'RBVM_DASHBOARD_CORE_V1',
    "heading.textContent = 'Dashboard'",
    'Current canonical catalog',
    'Current page decision signals',
    'CSV-first runs remain run-scoped',
    "json('/api/v1/cases?limit=100')",
]:
    if required not in core:
        raise AssertionError(f"stabilized dashboard marker missing: {required}")

if 'rbvm-dashboard-core.js' not in compile_sh or 'rbvm-dashboard-core.css' not in compile_sh:
    raise AssertionError('stabilized dashboard is not bundled')
if 'MAX_PAGES' in core or 'nextCursor' in core:
    raise AssertionError('stabilized dashboard must not crawl the full case catalog in the browser')
if "One dashboard renderer in the core SPA" not in doc:
    raise AssertionError("stabilization documentation is incomplete")

print("RBVM stabilization V1 checks: PASS")
