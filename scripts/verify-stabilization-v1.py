#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
compile_sh = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")
core = (ROOT / "src/main/resources/web/rbvm-dashboard-core.js").read_text(encoding="utf-8")
css = (ROOT / "src/main/resources/web/rbvm-dashboard-core.css").read_text(encoding="utf-8")
transform = (ROOT / "scripts/stabilize-frontend-runtime.py").read_text(encoding="utf-8")
ui = (ROOT / "src/main/resources/web/rbvm-ui.js").read_text(encoding="utf-8")
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
    'CSV-first runs remain run-scoped',
    "json('/api/v1/cases?limit=100')",
    'CVSS × EPSS decision landscape',
    'dashboard-core-donut',
    'dashboard-core-scatter',
]:
    if required not in core:
        raise AssertionError(f"stabilized dashboard marker missing: {required}")

if 'rbvm-dashboard-core.js' not in compile_sh or 'rbvm-dashboard-core.css' not in compile_sh:
    raise AssertionError('stabilized dashboard is not bundled')
if 'stabilize-frontend-runtime.py' not in compile_sh:
    raise AssertionError('legacy Overview bounded-read transform is not executed by compile.sh')
if 'MAX_PAGES' in core or 'nextCursor' in core:
    raise AssertionError('stabilized dashboard must not crawl the full case catalog in the browser')

legacy = "const [sum,cases]=await Promise.all([summary(),allCases()]);"
bounded = "const [sum,cases]=await Promise.all([summary(),json('/api/v1/cases?limit=100').then(data=>data.cases||[])]);"
if ui.count(legacy) != 1:
    raise AssertionError('legacy Overview source shape drifted; stabilization transform must fail closed')
if legacy not in transform or bounded not in transform or 'count != 1' not in transform:
    raise AssertionError('Overview stabilization transform is not exact/fail-closed')

for invalid_token in ['var(--surface-2)', 'var(--surface-3)', 'var(--muted)', 'var(--accent)']:
    if invalid_token in css:
        raise AssertionError(f'dashboard uses nonexistent theme token: {invalid_token}')
for required_token in ['var(--surface-subtle)', 'var(--text-muted)', 'var(--brand)', 'var(--danger)']:
    if required_token not in css:
        raise AssertionError(f'dashboard theme integration missing: {required_token}')

if "One dashboard renderer in the core SPA" not in doc:
    raise AssertionError("stabilization documentation is incomplete")

print("RBVM stabilization V1 checks: PASS")
