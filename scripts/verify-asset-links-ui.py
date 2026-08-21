#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "src/main/resources/web/asset-links.html"
text = HTML.read_text(encoding="utf-8")

ids = re.findall(r'\bid="([^"]+)"', text)
if len(ids) != len(set(ids)):
    raise AssertionError("asset-links.html contains duplicate ids")

for needle in [
    'sessionStorage.getItem(\'rbvmApiToken\')',
    'sessionStorage.setItem(\'rbvmApiToken\'',
    '/api/v1/scanner-assets',
    '/managed-asset-link',
    '/managed-asset-link/revisions',
    "'If-Match'",
    "response.headers.get('ETag')",
    'error.status === 412',
    'لا يتم اختيار هدف تلقائياً',
    'NEVER_ASSESSED',
    'textContent',
    '<dialog',
    'role="status"',
    '<table',
    'اختر بشكل صريح',
]:
    if needle not in text:
        raise AssertionError(f"asset link UI missing {needle!r}")

for forbidden in [
    'innerHTML',
    'document.write',
    'localStorage.',
    "method: 'DELETE'",
    "method: 'PATCH'",
]:
    if forbidden in text:
        raise AssertionError(f"asset link UI contains forbidden pattern {forbidden!r}")

refs = re.findall(r"byId\('([^']+)'\)", text)
missing = sorted(set(refs) - set(ids))
if missing:
    raise AssertionError(f"asset link UI references missing ids: {missing}")

print(f"Asset links UI checks: PASS ({len(ids)} unique ids)")
