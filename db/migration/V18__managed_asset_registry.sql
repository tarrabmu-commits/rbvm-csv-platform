BEGIN;

-- V18 introduces a customer-managed asset registry that is deliberately separate from rbvm.asset.
-- rbvm.asset remains scanner/source-profile identity. managed_asset is the tenant's durable business
-- inventory identity and may exist before any scanner has observed it.
CREATE TABLE rbvm.managed_asset (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    customer_asset_key text,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id),
    CHECK (customer_asset_key IS NULL OR length(trim(customer_asset_key)) > 0)
);

CREATE UNIQUE INDEX managed_asset_customer_key_idx
    ON rbvm.managed_asset (tenant_id, customer_asset_key)
    WHERE customer_asset_key IS NOT NULL;

-- Every customer edit is append-only. The root managed_asset row is stable identity; mutable
-- customer context lives only in numbered revisions so prior classifications remain auditable.
CREATE TABLE rbvm.managed_asset_revision (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    managed_asset_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    lifecycle_status text NOT NULL CHECK (lifecycle_status IN ('ACTIVE', 'RETIRED')),
    display_name text NOT NULL CHECK (length(trim(display_name)) > 0),
    environment text NOT NULL CHECK (
        environment IN (
            'PRODUCTION', 'PRE_PRODUCTION', 'DEVELOPMENT', 'TEST', 'SANDBOX',
            'DISASTER_RECOVERY', 'UNKNOWN'
        )
    ),
    business_service text NOT NULL CHECK (length(trim(business_service)) > 0),
    business_owner text NOT NULL CHECK (length(trim(business_owner)) > 0),
    business_criticality text NOT NULL CHECK (
        business_criticality IN ('MISSION_CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN')
    ),
    classification_method text NOT NULL CHECK (
        classification_method IN ('CUSTOMER_DIRECT', 'GUIDED')
    ),
    guide_contract_id text,
    guide_revision integer,
    context_source text NOT NULL CHECK (context_source = 'CUSTOMER_ASSET_REGISTRY'),
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    changed_by text NOT NULL CHECK (length(trim(changed_by)) > 0),
    change_note text NOT NULL DEFAULT '',
    recorded_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    CONSTRAINT managed_asset_one_numbered_revision
        UNIQUE (tenant_id, managed_asset_id, revision),
    CONSTRAINT managed_asset_revision_identity
        UNIQUE (tenant_id, managed_asset_id, id),
    CONSTRAINT managed_asset_guide_basis CHECK (
        (classification_method = 'CUSTOMER_DIRECT'
            AND guide_contract_id IS NULL AND guide_revision IS NULL)
        OR
        (classification_method = 'GUIDED'
            AND guide_contract_id IS NOT NULL
            AND length(trim(guide_contract_id)) > 0
            AND guide_revision IS NOT NULL
            AND guide_revision > 0)
    ),
    FOREIGN KEY (tenant_id, managed_asset_id)
        REFERENCES rbvm.managed_asset(tenant_id, id)
);

CREATE INDEX managed_asset_revision_time_idx
    ON rbvm.managed_asset_revision (
        tenant_id, managed_asset_id, revision DESC, recorded_at DESC
    );

-- This is a convenience projection only. History remains in managed_asset_revision and writers
-- must append a new revision rather than UPDATE or DELETE a prior one.
CREATE VIEW rbvm.current_managed_asset AS
SELECT DISTINCT ON (a.tenant_id, a.id)
    a.tenant_id,
    a.id AS managed_asset_id,
    a.customer_asset_key,
    a.created_at,
    r.id AS revision_id,
    r.revision,
    r.lifecycle_status,
    r.display_name,
    r.environment,
    r.business_service,
    r.business_owner,
    r.business_criticality,
    r.classification_method,
    r.guide_contract_id,
    r.guide_revision,
    r.context_source,
    r.evidence_sha256,
    r.changed_by,
    r.change_note,
    r.recorded_at
FROM rbvm.managed_asset a
JOIN rbvm.managed_asset_revision r
  ON r.tenant_id = a.tenant_id
 AND r.managed_asset_id = a.id
ORDER BY a.tenant_id, a.id, r.revision DESC;

CREATE VIEW rbvm.active_managed_asset AS
SELECT *
FROM rbvm.current_managed_asset
WHERE lifecycle_status = 'ACTIVE';

COMMENT ON TABLE rbvm.managed_asset IS
    'Stable tenant-owned asset identity. It is independent from scanner/source-profile asset identity and may exist before scanner discovery.';
COMMENT ON TABLE rbvm.managed_asset_revision IS
    'Append-only customer asset context/history. Edits and retire/reactivate operations append revisions; prior revisions must not be overwritten.';
COMMENT ON COLUMN rbvm.managed_asset.customer_asset_key IS
    'Optional immutable customer/CMDB stable identifier. Display names and classifications belong in revisions.';
COMMENT ON VIEW rbvm.current_managed_asset IS
    'Latest customer-managed asset revision only. This view is operational convenience and is not immutable evidence history.';
COMMENT ON VIEW rbvm.active_managed_asset IS
    'Current customer-managed assets whose latest lifecycle revision is ACTIVE.';

COMMIT;
