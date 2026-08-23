#!/usr/bin/env python3
"""Route the customer CSV workflow through the non-blocking job transport.

The source customer-flow module stays compatible with the legacy synchronous
transport. The product bundle opts into the V1 async job endpoint with an exact,
fail-closed transform until the frontend modules are consolidated.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: stabilize-csv-first-async-runtime.py <compiled-rbvm-ui.js>")

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
replacements = {
    "setStatus(status, `Collecting public intelligence for ${selected.name}…`);":
        "setStatus(status, `Starting public intelligence job for ${selected.name}…`);",
    "const response = await api('/api/v1/csv-first-enrichments', {":
        "const response = await api('/api/v1/csv-first-enrichment-jobs', {",
    "setStatus(status, `Enrichment complete. Opening Assets for ${candidates.length} asset${candidates.length === 1 ? '' : 's'}…`, 'success');":
        "setStatus(status, `Enrichment started in background. Opening Assets for ${candidates.length} asset${candidates.length === 1 ? '' : 's'}…`, 'success');",
}
for old, new in replacements.items():
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected exactly one async-flow source marker, found {count}: {old}")
    text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8")
print("CSV-first async runtime transform: PASS")
