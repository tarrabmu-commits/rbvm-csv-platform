#!/usr/bin/env python3
"""Apply bounded/retention-safe transforms to the dependency-free frontend runtime.

These are intentionally narrow, fail-closed build transforms while Frontend System V2 is
being consolidated. The stabilized Dashboard must not crawl the full catalog, and temporary
full-catalog case/asset/report arrays must not stay retained after SPA navigation.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: stabilize-frontend-runtime.py <compiled-rbvm-ui.js>")

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")


def replace_once(old, new, label):
    global text
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"frontend stabilization drift: {label} matched {count} times")
    text = text.replace(old, new, 1)


replace_once(
    "const [sum,cases]=await Promise.all([summary(),allCases()]);",
    "const [sum,cases]=await Promise.all([summary(),json('/api/v1/cases?limit=100').then(data=>data.cases||[])]);",
    "legacy Overview full-catalog read",
)

# Full-catalog arrays are useful while Analytics/Reports/Managed Assets are actively open,
# but keeping them in the global state after leaving the route prevents browser GC. Release
# those arrays at every SPA navigation boundary; API evidence/state is never changed.
replace_once(
    """  function navigate(path, params = null, replace = false) {\n    history[replace ? 'replaceState' : 'pushState']({}, '', url(path, params));\n    closeOverlay(); closeNav(); render();\n  }""",
    """  function navigate(path, params = null, replace = false) {\n    history[replace ? 'replaceState' : 'pushState']({}, '', url(path, params));\n    state.cases = []; state.assets = []; state.reportCases = null;\n    closeOverlay(); closeNav(); render();\n  }""",
    "SPA navigation cache release",
)

replace_once(
    "window.addEventListener('popstate',()=>{closeOverlay();render();});",
    "window.addEventListener('popstate',()=>{state.cases=[];state.assets=[];state.reportCases=null;closeOverlay();render();});",
    "history navigation cache release",
)

path.write_text(text, encoding="utf-8")
print("Frontend stabilization transform: PASS (bounded Overview + navigation cache release)")
