#!/usr/bin/env python3
"""Apply the bounded Overview read used by the stabilized runtime bundle.

This is intentionally a narrow, fail-closed build transform while Frontend System
V2 is being consolidated. It prevents the legacy Overview renderer from crawling
up to MAX_PAGES before the first-class Dashboard takes ownership of the route.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: stabilize-frontend-runtime.py <compiled-rbvm-ui.js>")

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = "const [sum,cases]=await Promise.all([summary(),allCases()]);"
new = "const [sum,cases]=await Promise.all([summary(),json('/api/v1/cases?limit=100').then(data=>data.cases||[])]);"
count = text.count(old)
if count != 1:
    raise RuntimeError(f"expected exactly one legacy Overview full-catalog read, found {count}")
text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8")
print("Frontend stabilization transform: PASS (Overview bounded to first 100 findings)")
