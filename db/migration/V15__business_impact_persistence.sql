BEGIN;

-- Business/Mission Impact remains independent, source-reported qualitative evidence.
CREATE TABLE rbvm.business_impact_snapshot (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    impact_source text NOT NULL CHECK (length(trim(impact_source)) > 0),
    source_sha256 char(64) NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
    observed_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    CONSTRAINT business_impact_one_source_observation
        UNIQUE (tenant_id, impact_source, observed_at),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id)
);

CREATE INDEX business_impact_snapshot_lookup_idx
    ON rbvm.business_impact_snapshot
       (tenant_id, impact_source, observed_at DESC, ingested_at DESC);

CREATE TABLE rbvm.business_impact_evidence (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    asset_identity_basis text NOT NULL CHECK (
        asset_identity_basis IN ('SOURCE_NAME_ONLY', 'SOURCE_STABLE_ID')
    ),
    asset_name_observed text NOT NULL CHECK (length(trim(asset_name_observed)) > 0),
    asset_source_id text,
    business_service text NOT NULL CHECK (length(trim(business_service)) > 0),
    business_service_normalized text NOT NULL CHECK (length(trim(business_service_normalized)) > 0),
    impact_dimension text NOT NULL CHECK (
        impact_dimension IN (
            'AVAILABILITY', 'INTEGRITY', 'CONFIDENTIALITY', 'SAFETY', 'FINANCIAL',
            'REGULATORY', 'OPERATIONAL', 'REPUTATIONAL', 'MISSION', 'OTHER', 'UNKNOWN'
        )
    ),
    impact_level text NOT NULL CHECK (
        impact_level IN ('SEVERE', 'HIGH', 'MODERATE', 'LOW', 'NEGLIGIBLE', 'UNKNOWN')
    ),
    impact_method text NOT NULL CHECK (
        impact_method IN (
            'BUSINESS_IMPACT_ANALYSIS', 'SERVICE_OWNER_ATTESTATION',
            'POLICY_CLASSIFICATION', 'INCIDENT_ANALYSIS', 'OTHER', 'UNKNOWN'
        )
    ),
    impact_statement text NOT NULL CHECK (length(trim(impact_statement)) > 0),
    ingested_at timestamptz NOT NULL,
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    UNIQUE (tenant_id, id),
    CONSTRAINT business_impact_identity_evidence_check CHECK (
        (asset_identity_basis = 'SOURCE_NAME_ONLY' AND asset_source_id IS NULL) OR
        (asset_identity_basis = 'SOURCE_STABLE_ID'
            AND asset_source_id IS NOT NULL AND length(trim(asset_source_id)) > 0)
    ),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES rbvm.asset(tenant_id, id),
    FOREIGN KEY (tenant_id, snapshot_id)
        REFERENCES rbvm.business_impact_snapshot(tenant_id, id)
);

CREATE UNIQUE INDEX business_impact_one_dimension_per_snapshot_idx
    ON rbvm.business_impact_evidence (
        tenant_id, asset_id, snapshot_id, business_service_normalized, impact_dimension
    );

CREATE INDEX business_impact_evidence_lookup_idx
    ON rbvm.business_impact_evidence
       (tenant_id, asset_id, business_service_normalized, impact_dimension, ingested_at DESC);

-- Latest impact stays independent per source, service, and impact dimension. No source arbitration,
-- level weighting, aggregation, or automatic conversion from Asset Context Business Criticality.
CREATE VIEW rbvm.current_business_impact_evidence AS
SELECT DISTINCT ON (
    e.tenant_id,
    e.asset_id,
    s.impact_source,
    e.business_service_normalized,
    e.impact_dimension
)
    e.id,
    e.tenant_id,
    e.asset_id,
    e.snapshot_id,
    sp.external_key AS source_profile_key,
    e.asset_identity_basis,
    e.asset_name_observed,
    e.asset_source_id,
    e.business_service,
    e.business_service_normalized,
    e.impact_dimension,
    e.impact_level,
    e.impact_method,
    e.impact_statement,
    e.ingested_at AS evidence_ingested_at,
    e.evidence_sha256,
    s.impact_source,
    s.source_sha256,
    s.observed_at,
    s.ingested_at AS snapshot_ingested_at
FROM rbvm.business_impact_evidence e
JOIN rbvm.business_impact_snapshot s
  ON s.tenant_id = e.tenant_id
 AND s.id = e.snapshot_id
JOIN rbvm.asset a
  ON a.tenant_id = e.tenant_id
 AND a.id = e.asset_id
JOIN rbvm.source_profile sp
  ON sp.tenant_id = a.tenant_id
 AND sp.id = a.source_profile_id
ORDER BY
    e.tenant_id,
    e.asset_id,
    s.impact_source,
    e.business_service_normalized,
    e.impact_dimension,
    s.observed_at DESC,
    e.ingested_at DESC,
    e.id DESC;

-- Findings inherit zero or more current impact observations through their asset. Missing impact
-- evidence remains absent and is never fabricated as LOW, NEGLIGIBLE, or UNKNOWN.
CREATE VIEW rbvm.finding_business_impact_evidence AS
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
    (i.id IS NOT NULL) AS business_impact_observed,
    i.source_profile_key AS impact_source_profile_key,
    i.asset_identity_basis AS impact_asset_identity_basis,
    i.asset_name_observed AS impact_asset_name_observed,
    i.asset_source_id AS impact_asset_source_id,
    i.business_service,
    i.impact_dimension,
    i.impact_level,
    i.impact_method,
    i.impact_statement,
    i.impact_source,
    i.source_sha256 AS impact_source_sha256,
    i.observed_at AS impact_observed_at,
    i.evidence_ingested_at AS impact_evidence_ingested_at,
    i.snapshot_ingested_at AS impact_snapshot_ingested_at
FROM rbvm.operational_finding f
LEFT JOIN rbvm.current_business_impact_evidence i
  ON i.tenant_id = f.tenant_id
 AND i.asset_id = f.asset_id;

COMMENT ON TABLE rbvm.business_impact_snapshot IS
    'Immutable tenant-scoped provenance for Business/Mission Impact source-artifact observations.';
COMMENT ON TABLE rbvm.business_impact_evidence IS
    'Immutable source-reported qualitative Business/Mission Impact evidence for already-canonical asset/service pairs. Impact levels are not numeric weights.';
COMMENT ON VIEW rbvm.current_business_impact_evidence IS
    'Latest impact independently per tenant, asset, impact source, normalized business service, and dimension. No source arbitration or aggregate impact score.';
COMMENT ON VIEW rbvm.finding_business_impact_evidence IS
    'Canonical findings joined by asset to zero or more current Business/Mission Impact observations. Missing evidence remains absent.';

COMMIT;
