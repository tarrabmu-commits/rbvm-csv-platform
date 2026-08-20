#!/usr/bin/env python3
from pathlib import Path
import sys


def require(text: str, needle: str, where: str) -> None:
    if needle not in text:
        raise AssertionError(f"{where} is missing required invariant: {needle}")


def forbid(text: str, needle: str, where: str) -> None:
    if needle in text:
        raise AssertionError(f"{where} contains forbidden construct: {needle}")


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    api_path = root / "src/main/java/io/rbvm/csv/ManagedAssetApi.java"
    registry_path = root / "src/main/java/io/rbvm/asset/ManagedAssetRegistry.java"
    read_store_path = root / "src/main/java/io/rbvm/postgres/PostgresManagedAssetReadStore.java"
    server_path = root / "src/main/java/io/rbvm/csv/CsvPlatformServer.java"
    router_path = root / "src/main/java/io/rbvm/csv/ManagedAssetHttpRouter.java"
    factory_path = root / "src/main/java/io/rbvm/postgres/CanonicalProjectionFactory.java"
    openapi_path = root / "api/openapi.yaml"

    api = api_path.read_text(encoding="utf-8")
    registry = registry_path.read_text(encoding="utf-8")
    read_store = read_store_path.read_text(encoding="utf-8")
    server = server_path.read_text(encoding="utf-8")
    router = router_path.read_text(encoding="utf-8")
    factory = factory_path.read_text(encoding="utf-8")
    openapi = openapi_path.read_text(encoding="utf-8")

    for needle in (
        '"customerAssetKey", "displayName", "environment", "businessService"',
        '"lifecycleStatus", "displayName", "environment", "businessService"',
        '"changedBy"',
        '"recordedAt"',
        '"contextSource"',
        '"evidenceSha256"',
        'MANAGED_ASSET_PRECONDITION_REQUIRED',
        'MANAGED_ASSET_PRECONDITION_FAILED',
        'INVALID_IF_MATCH',
        'MAXIMUM_BODY_BYTES = 16 * 1024',
        'UUID.randomUUID()',
        'revisionDraft(values, LifecycleStatus.ACTIVE, actorId)',
        'Map.of("Location", "/api/v1/managed-assets/"',
        'headers.put("ETag", etag(asset.currentRevision()))',
        'Nested JSON values are not supported by the managed asset contract',
        'Unpaired low surrogate in JSON unicode escape',
    ):
        require(api, needle, api_path.name)

    # Audit and immutable server-owned values must never become accepted request fields.
    create_fields = api.split('private static final Set<String> CREATE_FIELDS', 1)[1].split(');', 1)[0]
    revision_fields = api.split('private static final Set<String> REVISION_FIELDS', 1)[1].split(');', 1)[0]
    for forbidden in ('"changedBy"', '"recordedAt"', '"contextSource"', '"evidenceSha256"', '"revision"'):
        forbid(create_fields, forbidden, "CREATE_FIELDS")
        forbid(revision_fields, forbidden, "REVISION_FIELDS")

    for needle in (
        'ManagedAssetPage list(',
        'Optional<RevisionPage> history(',
        'enum LifecycleFilter',
    ):
        require(registry, needle, registry_path.name)
    lifecycle_block = registry.split('enum LifecycleFilter', 1)[1].split('}', 1)[0]
    for lifecycle in ('ALL', 'ACTIVE', 'RETIRED'):
        require(lifecycle_block, lifecycle, 'LifecycleFilter')

    for needle in (
        'FROM rbvm.current_managed_asset',
        'WHERE tenant_id = ?',
        'AND managed_asset_id > ?',
        'ORDER BY managed_asset_id ASC',
        'FROM rbvm.managed_asset_revision',
        'AND revision < ?',
        'ORDER BY revision DESC',
        'Connection.TRANSACTION_REPEATABLE_READ',
    ):
        require(read_store, needle, read_store_path.name)

    for forbidden in (
        'UPDATE rbvm.managed_asset',
        'UPDATE rbvm.managed_asset_revision',
        'DELETE FROM rbvm.managed_asset',
        'DELETE FROM rbvm.managed_asset_revision',
        'TRUNCATE rbvm.managed_asset',
        'FROM rbvm.asset',
        'JOIN rbvm.asset',
    ):
        forbid(read_store, forbidden, read_store_path.name)

    for needle in (
        'ManagedAssetHttpRouter.inNamespace(path)',
        'authorize(exchange, requiredRole)',
        'managedAssetRouter.orElseThrow',
        'runtime.managedAssetRegistry()',
        'managedAssets',
    ):
        require(server, needle, server_path.name)

    managed_route = server.split('ManagedAssetHttpRouter.inNamespace(path)', 1)[1]
    if managed_route.find('authorize(exchange, requiredRole)') > managed_route.find(
            'managedAssetRouter.orElseThrow'):
        raise AssertionError(
            'Managed Asset capability lookup must occur only after route authorization'
        )

    for needle in (
        '/api/v1/managed-assets',
        'ApiRole.VIEWER',
        'ApiRole.OPERATOR',
        'If-Match',
        'Content-Type',
    ):
        require(router, needle, router_path.name)
    forbid(router, 'DELETE', router_path.name)

    require(factory, 'Optional<ManagedAssetRegistry> managedAssetRegistry', factory_path.name)
    require(factory, 'installedVersion >= 18', factory_path.name)
    require(factory, 'new PostgresManagedAssetRegistry(connections, false)', factory_path.name)

    for needle in (
        '/managed-assets:',
        '/managed-assets/{managedAssetId}:',
        '/managed-assets/{managedAssetId}/revisions:',
        'If-Match',
        'ETag',
        "'428':",
        "'412':",
    ):
        require(openapi, needle, openapi_path.name)
    forbid(openapi, 'deleteManagedAsset', openapi_path.name)

    print("Managed asset API structural checks: PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(error, file=sys.stderr)
        raise
