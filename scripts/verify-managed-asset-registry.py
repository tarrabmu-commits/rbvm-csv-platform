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
    migration_path = root / "db/migration/V18__managed_asset_registry.sql"
    store_path = root / "src/main/java/io/rbvm/postgres/PostgresManagedAssetRegistry.java"
    migrator_path = root / "src/main/java/io/rbvm/postgres/PostgresMigrator.java"
    role_path = root / "db/security/runtime-role.sql"

    migration = migration_path.read_text(encoding="utf-8")
    store = store_path.read_text(encoding="utf-8")
    migrator = migrator_path.read_text(encoding="utf-8")
    role = role_path.read_text(encoding="utf-8")

    for needle in (
        "CREATE TABLE rbvm.managed_asset (",
        "CREATE TABLE rbvm.managed_asset_revision (",
        "CREATE VIEW rbvm.current_managed_asset AS",
        "CREATE VIEW rbvm.active_managed_asset AS",
        "customer_asset_key text",
        "UNIQUE (tenant_id, managed_asset_id, revision)",
        "lifecycle_status IN ('ACTIVE', 'RETIRED')",
        "classification_method IN ('CUSTOMER_DIRECT', 'GUIDED')",
        "context_source = 'CUSTOMER_ASSET_REGISTRY'",
        "evidence_sha256 char(64)",
        "environment IN (",
        "business_criticality IN ('MISSION_CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN')",
        "Append-only customer asset context/history",
        "independent from scanner/source-profile asset identity",
    ):
        require(migration, needle, migration_path.name)

    for forbidden in (
        "REFERENCES rbvm.asset(tenant_id, id)",
        "risk_score",
        "priority_tier",
        "sla_days",
        "cvss",
        "epss",
        "known_exploited",
    ):
        forbid(migration.lower(), forbidden.lower(), migration_path.name)

    require(migrator, 'new Migration(18, "V18__managed_asset_registry.sql")', migrator_path.name)

    for needle in (
        "REQUIRED_SCHEMA_VERSION = 18",
        "Connection.TRANSACTION_SERIALIZABLE",
        "pg_advisory_xact_lock",
        "INSERT INTO rbvm.managed_asset(",
        "INSERT INTO rbvm.managed_asset_revision(",
        "MutationStatus.REVISION_CONFLICT",
        "MutationStatus.CUSTOMER_KEY_CONFLICT",
        "MutationStatus.REPLAYED",
        "expectedRevision + 1",
        "currentRevision + 1",
        "ManagedAsset.CONTEXT_SOURCE",
    ):
        require(store, needle, store_path.name)

    for forbidden in (
        "UPDATE rbvm.managed_asset",
        "UPDATE rbvm.managed_asset_revision",
        "DELETE FROM rbvm.managed_asset",
        "DELETE FROM rbvm.managed_asset_revision",
        "TRUNCATE rbvm.managed_asset",
    ):
        forbid(store, forbidden, store_path.name)

    for needle in (
        "rbvm.managed_asset,",
        "rbvm.managed_asset_revision",
        "rbvm.current_managed_asset,",
        "rbvm.active_managed_asset",
        "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.managed_asset FROM rbvm_runtime;",
        "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.managed_asset_revision FROM rbvm_runtime;",
    ):
        require(role, needle, role_path.name)

    print("Managed asset registry structural checks: PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(error, file=sys.stderr)
        raise
