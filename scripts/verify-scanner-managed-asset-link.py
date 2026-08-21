#!/usr/bin/env python3
from pathlib import Path
import sys


def require(text: str, needle: str, where: str) -> None:
    if needle not in text:
        raise AssertionError(f"{where} is missing required invariant: {needle}")


def forbid(text: str, needle: str, where: str) -> None:
    if needle.lower() in text.lower():
        raise AssertionError(f"{where} contains forbidden construct: {needle}")


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    migration_path = root / "db/migration/V19__scanner_managed_asset_link.sql"
    store_path = root / "src/main/java/io/rbvm/postgres/PostgresScannerManagedAssetLinkRegistry.java"
    domain_path = root / "src/main/java/io/rbvm/asset/ScannerManagedAssetLink.java"
    registry_path = root / "src/main/java/io/rbvm/asset/ScannerManagedAssetLinkRegistry.java"
    migrator_path = root / "src/main/java/io/rbvm/postgres/PostgresMigrator.java"
    factory_path = root / "src/main/java/io/rbvm/postgres/CanonicalProjectionFactory.java"
    role_path = root / "db/security/runtime-role.sql"
    doc_path = root / "docs/SCANNER_MANAGED_ASSET_LINK_V1.md"

    migration = migration_path.read_text(encoding="utf-8")
    store = store_path.read_text(encoding="utf-8")
    domain = domain_path.read_text(encoding="utf-8")
    registry = registry_path.read_text(encoding="utf-8")
    migrator = migrator_path.read_text(encoding="utf-8")
    factory = factory_path.read_text(encoding="utf-8")
    role = role_path.read_text(encoding="utf-8")
    doc = doc_path.read_text(encoding="utf-8")

    for needle in (
        "CREATE TABLE rbvm.scanner_managed_asset_link_event (",
        "link_status IN ('LINKED', 'UNLINKED')",
        "link_method = 'CUSTOMER_CONFIRMED'",
        "REFERENCES rbvm.asset(tenant_id, id)",
        "REFERENCES rbvm.managed_asset(tenant_id, id)",
        "UNIQUE (tenant_id, scanner_asset_id, revision)",
        "CREATE VIEW rbvm.current_scanner_managed_asset_link AS",
        "CREATE VIEW rbvm.active_scanner_managed_asset_link AS",
        "latest UNLINKED",
        "No hostname/OS/product inference is permitted",
    ):
        require(migration, needle, migration_path.name)

    # These constructs are forbidden everywhere in the link persistence contract.
    for forbidden in (
        "risk_score", "priority_tier", "sla_days", "cvss", "epss", "known_exploited"
    ):
        forbid(migration, forbidden, migration_path.name)
        forbid(store, forbidden, store_path.name)

    # Scanner presentation attributes may be read by V23's list endpoint, but they must remain
    # absent from the mutation/current/history decision machinery. This preserves V21's
    # no-inference invariant while allowing operators to identify the scanner row they are
    # explicitly linking.
    list_marker = "    public ScannerAssetPage list(int limit, UUID afterId) throws IOException {"
    schema_marker = "    public int schemaVersion() {"
    if store.count(list_marker) != 1 or store.count(schema_marker) != 1:
        raise AssertionError("Could not isolate the read-only V23 scanner list method")
    before_list, tail = store.split(list_marker, 1)
    _list_body, after_list = tail.split(schema_marker, 1)
    decision_surface = before_list + schema_marker + after_list
    for forbidden in ("normalized_observed_name", "os_name_raw"):
        forbid(migration, forbidden, migration_path.name)
        forbid(decision_surface, forbidden, "link mutation/current/history decision surface")

    for needle in (
        'new Migration(19, "V19__scanner_managed_asset_link.sql")',
        "REQUIRED_SCHEMA_VERSION = 19",
        "Connection.TRANSACTION_SERIALIZABLE",
        "pg_advisory_xact_lock",
        "expectedRevision + 1",
        "currentRevision + 1",
        "MutationStatus.REVISION_CONFLICT",
        "MutationStatus.REPLAYED",
        "SELECT 1 FROM rbvm.asset WHERE tenant_id = ? AND id = ?",
        "SELECT 1 FROM rbvm.managed_asset WHERE tenant_id = ? AND id = ?",
        "INSERT INTO rbvm.scanner_managed_asset_link_event(",
    ):
        require(migrator + store, needle, "migrator/store")

    for forbidden in (
        "UPDATE rbvm.scanner_managed_asset_link_event",
        "DELETE FROM rbvm.scanner_managed_asset_link_event",
        "TRUNCATE rbvm.scanner_managed_asset_link_event",
    ):
        forbid(store, forbidden, store_path.name)

    for needle in (
        "expectedRevision=0 means no link decision has ever been recorded",
        "SCANNER_ASSET_NOT_FOUND",
        "MANAGED_ASSET_NOT_FOUND",
        "CurrentLookup(boolean scannerAssetExists",
        "LinkMethod.CUSTOMER_CONFIRMED",
        "CONTRACT_ID = \"SCANNER_MANAGED_ASSET_LINK_V1\"",
    ):
        require(registry + domain, needle, "domain/registry")

    for needle in (
        "rbvm.scanner_managed_asset_link_event",
        "rbvm.current_scanner_managed_asset_link",
        "rbvm.active_scanner_managed_asset_link",
        "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.scanner_managed_asset_link_event FROM rbvm_runtime;",
    ):
        require(role, needle, role_path.name)

    for needle in (
        "Optional<ScannerManagedAssetLinkRegistry>",
        "installedVersion >= 19",
        "new PostgresScannerManagedAssetLinkRegistry(connections, false)",
    ):
        require(factory, needle, factory_path.name)

    for needle in (
        "never assessed / no explicit link decision",
        "explicitly no current link",
        "database migration V19",
        "RBVM_POLICY",
        "STANDARD_DERIVED",
        "generic association-evidence layer",
    ):
        require(doc, needle, doc_path.name)

    print("Scanner-managed asset link structural checks: PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(error, file=sys.stderr)
        raise
