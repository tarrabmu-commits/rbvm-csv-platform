#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

api = text("src/main/java/io/rbvm/csv/ScannerManagedAssetLinkApi.java")
router = text("src/main/java/io/rbvm/csv/ScannerManagedAssetLinkHttpRouter.java")
server = text("src/main/java/io/rbvm/csv/CsvPlatformServer.java")
registry = text("src/main/java/io/rbvm/asset/ScannerManagedAssetLinkRegistry.java")
pg = text("src/main/java/io/rbvm/postgres/PostgresScannerManagedAssetLinkRegistry.java")
openapi = text("api/openapi.yaml")
verify = text("scripts/verify.sh")

required_api = [
    'SCANNER_MANAGED_ASSET_LINK_API_V1',
    'sma-r0-',
    'NEVER_ASSESSED',
    'SCANNER_MANAGED_ASSET_LINK_PRECONDITION_REQUIRED',
    'SCANNER_MANAGED_ASSET_LINK_PRECONDITION_FAILED',
    'UNKNOWN_SCANNER_MANAGED_ASSET_LINK_FIELDS',
    'ChangeDraft',
    'actorId',
    'If-Match',
]
for needle in required_api:
    if needle not in api:
        raise AssertionError(f"link API missing {needle!r}")

for needle in [
    '/api/v1/scanner-assets',
    '/managed-asset-link',
    'ApiRole.VIEWER',
    'ApiRole.OPERATOR',
    'If-Match',
]:
    if needle not in router:
        raise AssertionError(f"link router missing {needle!r}")

for forbidden in ['"DELETE"', '"PATCH"']:
    if forbidden in router:
        raise AssertionError(f"link router must not expose {forbidden}")

for needle in ['ScannerAssetPage', 'ScannerAssetSummary', 'list(int limit, UUID afterId)']:
    if needle not in registry:
        raise AssertionError(f"registry list contract missing {needle!r}")

for needle in [
    'JOIN rbvm.source_profile',
    'LEFT JOIN rbvm.current_scanner_managed_asset_link',
    'ORDER BY a.id ASC',
    'tenant_id = ?',
]:
    if needle not in pg:
        raise AssertionError(f"PostgreSQL scanner list missing {needle!r}")

for needle in [
    'scannerManagedAssetLinks',
    'ScannerManagedAssetLinkHttpRouter.inNamespace',
    'SCANNER_MANAGED_ASSET_LINK_PERSISTENCE_UNAVAILABLE',
    '/asset-links',
]:
    if needle not in server:
        raise AssertionError(f"server wiring missing {needle!r}")

for needle in [
    '/scanner-assets:',
    '/scanner-assets/{scannerAssetId}/managed-asset-link:',
    '/scanner-assets/{scannerAssetId}/managed-asset-link/revisions:',
    'ScannerManagedAssetLinkCapability:',
    'ScannerAssetPage:',
    'ScannerManagedAssetLinkRevisionRequest:',
    'version: 0.23.0',
]:
    if needle not in openapi:
        raise AssertionError(f"OpenAPI V23 missing {needle!r}")

if 'verify-scanner-managed-asset-link-api.py' not in verify:
    raise AssertionError('verify.sh does not invoke V23 link API verifier')

print('Scanner-managed asset link API structural checks: PASS')
