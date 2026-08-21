#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
js=(ROOT/"src/main/resources/web/rbvm-ui.js").read_text(encoding="utf-8")
for needle in ("async function scannerLinks","async function openScannerLink","/api/v1/scanner-assets?limit=100","/managed-asset-link`","`${path}/revisions`","`${path}/revisions?limit=20`","response.headers.get('ETag')","'If-Match':etag","error.status===412","LINKED","UNLINKED","Not assessed differs from Unlinked","RBVM never chooses a managed-asset target automatically","Append-only link decisions","managedAssetId"):
    if needle not in js: raise AssertionError(f"scanner-link V2 UI missing {needle!r}")
for forbidden in ("method:'DELETE'","method:'PATCH'","sessionStorage","rbvmApiToken"):
    if forbidden in js: raise AssertionError(f"scanner-link V2 UI contains forbidden pattern {forbidden!r}")
print("Scanner↔Managed Asset Link V2 UI checks: PASS")
