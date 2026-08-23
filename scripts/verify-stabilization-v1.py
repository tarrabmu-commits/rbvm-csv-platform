#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
compile_sh = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")
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
    "pageHeader('Dashboard'",
    "Current canonical catalog",
    "Current page decision signals",
    "CSV-first runs remain run-scoped",
]:
    if required not in ui:
        raise AssertionError(f"first-class dashboard marker missing: {required}")

if "One dashboard renderer in the core SPA" not in doc:
    raise AssertionError("stabilization documentation is incomplete")

print("RBVM stabilization V1 checks: PASS")
