BEGIN;

-- Organizational asset context remains independent evidence. One validated source-artifact
-- observation is persisted separately from its per-asset rows so source bytes and observation
-- time stay auditable without mutating canonical scanner asset identity.
CREATE TABLE rbvm.asset_context_snapshot (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    context_source text NOT NULL CHECK (length(trim(context_source)) > 0),
    source_sha256 char(64) NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
    observed_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    CONSTRAINT asset_context_one_source_observation
        UNIQUE (tenant_id, context_source, observed_at),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id)
);

CREATE INDEX asset_context_snapshot_lookup_idx
    ON rbvm.asset_context_snapshot
       (tenant_id, context_source, observed_at DESC, ingested_at DESC);

CREATE TABLE rbvm.asset_context_evidence (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    asset_identity_basis text NOT NULL CHECK (
        asset_identity_basis IN ('SOURCE_NAME_ONLY', 'SOURCE_STABLE_ID')
    ),
    asset_name_observed text NOT NULL CHECK (length(trim(asset_name_observed)) > 0),
    asset_source_id text,
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
    ingested_at timestamptz NOT NULL,
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    UNIQUE (tenant_id, id),
    CONSTRAINT asset_context_one_asset_per_snapshot
        UNIQUE (tenant_id, asset_id, snapshot_id),
    CONSTRAINT asset_context_identity_evidence_check CHECK (
        (asset_identity_basis = 'SOURCE_NAME_ONLY' AND asset_source_id IS NULL) OR
        (asset_identity_basis = 'SOURCE_STABLE_ID'
            AND asset_source_id IS NOT NULL AND length(trim(asset_source_id)) > 0)
    ),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES rbvm.asset(tenant_id, id),
    FOREIGN KEY (tenant_id, snapshot_id)
        REFERENCES rbvm.asset_context_snapshot(tenant_id, id)
);

CREATE INDEX asset_context_evidence_lookup_idx
    ON rbvm.asset_context_evidence
       (tenant_id, asset_id, snapshot_id, ingested_at DESC);

-- Current context is latest independently per source. There is deliberately no cross-source
-- precedence or arbitration here; downstream decision methodology must make any such policy explicit.
CREATE VIEW rbvm.current_asset_context_evidence AS
SELECT DISTINCT ON (e.tenant_id, e.asset_id, s.context_source)
    e.id,
    e.tenant_id,
    e.asset_id,
    e.snapshot_id,
    sp.external_key AS source_profile_key,
    e.asset_identity_basis,
    e.asset_name_observed,
    e.asset_source_id,
    e.environment,
    e.business_service,
    e.business_owner,
    e.business_criticality,
    e.ingested_at AS evidence_ingested_at,
    e.evidence_sha256,
    s.context_source,
    s.source_sha256,
    s.observed_at,
    s.ingested_at AS snapshot_ingested_at
FROM rbvm.asset_context_evidence e
JOIN rbvm.asset_context_snapshot s
  ON s.tenant_id = e.tenant_id
 AND s.id = e.snapshot_id
JOIN rbvm.asset a
  ON a.tenant_id = e.tenant_id
 AND a.id = e.asset_id
JOIN rbvm.source_profile sp
  ON sp.tenant_id = a.tenant_id
 AND sp.id = a.source_profile_id
ORDER BY e.tenant_id, e.asset_id, s.context_source,
         s.observed_at DESC, e.ingested_at DESC, e.id DESC;

-- Findings inherit zero or more current organizational-context observations through their asset.
-- Multiple context sources intentionally remain multiple rows. Missing context remains NULL/false.
CREATE VIEW rbvm.finding_asset_context_evidence AS
SELECT
    f.tenant_id,
    f.exposure_id AS finding_id,
    f.case_id,
    f.source_profile_id,
    f.source_contract_id,
    f.asset_id,
    f.asset_name,
    f.vulnerability_id,
    f.cve_id,
    f.component_id,
    f.product_name,
    f.package_version,
    f.package_architecture,
    f.evidence_state,
    f.current_severity AS wazuh_severity,
    (c.id IS NOT NULL) AS asset_context_observed,
    c.source_profile_key AS context_source_profile_key,
    c.asset_identity_basis AS context_asset_identity_basis,
    c.asset_name_observed AS context_asset_name_observed,
    c.asset_source_id AS context_asset_source_id,
    c.environment,
    c.business_service,
    c.business_owner,
    c.business_criticality,
    c.context_source,
    c.source_sha256 AS context_source_sha256,
    c.observed_at AS context_observed_at,
    c.evidence_ingested_at AS context_evidence_ingested_at,
    c.snapshot_ingested_at AS context_snapshot_ingested_at
FROM rbvm.operational_finding f
LEFT JOIN rbvm.current_asset_context_evidence c
  ON c.tenant_id = f.tenant_id
 AND c.asset_id = f.asset_id;

COMMENT ON TABLE rbvm.asset_context_snapshot IS
    'Immutable tenant-scoped provenance for organizational asset-context source-artifact observations.';
COMMENT ON TABLE rbvm.asset_context_evidence IS
    'Immutable organizational context evidence for already-canonical assets. Importers must not create scanner assets from context rows.';
COMMENT ON VIEW rbvm.current_asset_context_evidence IS
    'Latest context independently per tenant, asset, and context source. It does not arbitrate sources or derive risk, priority, SLA, reachability, CVSS/KEV/EPSS combinations, or business-loss values.';
COMMENT ON VIEW rbvm.finding_asset_context_evidence IS
    'Canonical findings joined by asset to zero or more current context-source observations. Missing context remains NULL with asset_context_observed=false.';

COMMIT;
