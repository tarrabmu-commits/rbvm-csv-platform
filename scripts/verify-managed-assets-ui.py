#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
js=(ROOT/"src/main/resources/web/rbvm-ui.js").read_text(encoding="utf-8")
for needle in ("async function renderAssets","async function managedAssets","async function openAsset","function createAsset","function reviseAsset","function assetModel","/api/v1/managed-assets","/revisions`,{method:'POST'","response.headers.get('ETag')","'If-Match':etag","error.status===412","MISSION_CRITICAL","DISASTER_RECOVERY","CUSTOMER_DIRECT","GUIDED","Immutable customer-managed asset revisions","Concurrent changes return a conflict","customerAssetKey","businessCriticality","classificationMethod"):
    if needle not in js: raise AssertionError(f"managed-assets V2 UI missing {needle!r}")
for forbidden in ("method:'DELETE'","method:'PATCH'","sessionStorage","rbvmApiToken"):
    if forbidden in js: raise AssertionError(f"managed-assets V2 UI contains forbidden pattern {forbidden!r}")
print("Managed assets V2 UI checks: PASS")
