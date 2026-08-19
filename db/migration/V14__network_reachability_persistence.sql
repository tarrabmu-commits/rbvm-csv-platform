BEGIN;

-- Network reachability is independent technical evidence. Source-artifact provenance is stored
-- separately from endpoint rows so replay/conflict semantics remain explicit and immutable.
CREATE TABLE rbvm.network_reachability_snapshot (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    evidence_source text NOT NULL CHECK (length(trim(evidence_source)) > 0),
    source_sha256 char(64) NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
    observed_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    CONSTRAINT network_reachability_one_source_observation
        UNIQUE (tenant_id, evidence_source, observed_at),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id)
);

CREATE INDEX network_reachability_snapshot_lookup_idx
    ON rbvm.network_reachability_snapshot
       (tenant_id, evidence_source, observed_at DESC, ingested_at DESC);

CREATE TABLE rbvm.network_reachability_evidence (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    asset_identity_basis text NOT NULL CHECK (
        asset_identity_basis IN ('SOURCE_NAME_ONLY', 'SOURCE_STABLE_ID')
    ),
    asset_name_observed text NOT NULL CHECK (length(trim(asset_name_observed)) > 0),
    asset_source_id text,
    origin_scope text NOT NULL CHECK (
        origin_scope IN (
            'INTERNET', 'EXTERNAL_PARTNER', 'INTERNAL_ENTERPRISE',
            'LOCAL_SEGMENT', 'OTHER', 'UNKNOWN'
        )
    ),
    origin_label text NOT NULL CHECK (length(trim(origin_label)) > 0),
    transport_protocol text NOT NULL CHECK (
        transport_protocol IN ('TCP', 'UDP', 'ICMP', 'OTHER', 'UNKNOWN')
    ),
    target_port integer CHECK (target_port IS NULL OR target_port BETWEEN 1 AND 65535),
    target_service text NOT NULL CHECK (length(trim(target_service)) > 0),
    reachability_status text NOT NULL CHECK (
        reachability_status IN ('REACHABLE', 'NOT_REACHABLE', 'UNKNOWN')
    ),
    reachability_method text NOT NULL CHECK (
        reachability_method IN (
            'ACTIVE_PROBE', 'CONTROL_PLANE', 'FIREWALL_POLICY', 'CLOUD_CONFIGURATION',
            'PASSIVE_OBSERVATION', 'OTHER', 'UNKNOWN'
        )
    ),
    ingested_at timestamptz NOT NULL,
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    UNIQUE (tenant_id, id),
    CONSTRAINT network_reachability_identity_evidence_check CHECK (
        (asset_identity_basis = 'SOURCE_NAME_ONLY' AND asset_source_id IS NULL) OR
        (asset_identity_basis = 'SOURCE_STABLE_ID'
            AND asset_source_id IS NOT NULL AND length(trim(asset_source_id)) > 0)
    ),
    CONSTRAINT network_reachability_transport_port_check CHECK (
        (transport_protocol IN ('TCP', 'UDP') AND target_port IS NOT NULL) OR
        (transport_protocol = 'ICMP' AND target_port IS NULL) OR
        (transport_protocol IN ('OTHER', 'UNKNOWN'))
    ),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES rbvm.asset(tenant_id, id),
    FOREIGN KEY (tenant_id, snapshot_id)
        REFERENCES rbvm.network_reachability_snapshot(tenant_id, id)
);

-- PostgreSQL 14 does not provide NULLS NOT DISTINCT for unique constraints. Port 0 is forbidden by
-- the table check, so COALESCE(target_port, 0) is only an index identity token for portless evidence.
CREATE UNIQUE INDEX network_reachability_one_endpoint_per_snapshot_idx
    ON rbvm.network_reachability_evidence (
        tenant_id,
        asset_id,
        snapshot_id,
        origin_scope,
        origin_label,
        transport_protocol,
        COALESCE(target_port, 0)
    );

CREATE INDEX network_reachability_evidence_lookup_idx
    ON rbvm.network_reachability_evidence
       (tenant_id, asset_id, snapshot_id, origin_scope, transport_protocol, ingested_at DESC);

-- Current reachability remains latest independently per evidence source + origin + endpoint. There is
-- deliberately no source arbitration and no asset-wide internet-exposed boolean derived here.
CREATE VIEW rbvm.current_network_reachability_evidence AS
SELECT DISTINCT ON (
    e.tenant_id,
    e.asset_id,
    s.evidence_source,
    e.origin_scope,
    e.origin_label,
    e.transport_protocol,
    COALESCE(e.target_port, 0)
)
    e.id,
    e.tenant_id,
    e.asset_id,
    e.snapshot_id,
    sp.external_key AS source_profile_key,
    e.asset_identity_basis,
    e.asset_name_observed,
    e.asset_source_id,
    e.origin_scope,
    e.origin_label,
    e.transport_protocol,
    e.target_port,
    e.target_service,
    e.reachability_status,
    e.reachability_method,
    e.ingested_at AS evidence_ingested_at,
    e.evidence_sha256,
    s.evidence_source,
    s.source_sha256,
    s.observed_at,
    s.ingested_at AS snapshot_ingested_at
FROM rbvm.network_reachability_evidence e
JOIN rbvm.network_reachability_snapshot s
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
    s.evidence_source,
    e.origin_scope,
    e.origin_label,
    e.transport_protocol,
    COALESCE(e.target_port, 0),
    s.observed_at DESC,
    e.ingested_at DESC,
    e.id DESC;

-- Findings inherit zero or more current scoped reachability observations through their asset.
-- Missing evidence remains NULL/false; it is never converted to NOT_REACHABLE.
CREATE VIEW rbvm.finding_network_reachability_evidence AS
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
    (r.id IS NOT NULL) AS network_reachability_observed,
    r.source_profile_key AS reachability_source_profile_key,
    r.asset_identity_basis AS reachability_asset_identity_basis,
    r.asset_name_observed AS reachability_asset_name_observed,
    r.asset_source_id AS reachability_asset_source_id,
    r.origin_scope,
    r.origin_label,
    r.transport_protocol,
    r.target_port,
    r.target_service,
    r.reachability_status,
    r.reachability_method,
    r.evidence_source,
    r.source_sha256 AS reachability_source_sha256,
    r.observed_at AS reachability_observed_at,
    r.evidence_ingested_at AS reachability_evidence_ingested_at,
    r.snapshot_ingested_at AS reachability_snapshot_ingested_at
FROM rbvm.operational_finding f
LEFT JOIN rbvm.current_network_reachability_evidence r
  ON r.tenant_id = f.tenant_id
 AND r.asset_id = f.asset_id;

COMMENT ON TABLE rbvm.network_reachability_snapshot IS
    'Immutable tenant-scoped provenance for network-reachability source-artifact observations.';
COMMENT ON TABLE rbvm.network_reachability_evidence IS
    'Immutable origin- and endpoint-scoped network reachability evidence for already-canonical assets. Importers must not create scanner assets from reachability rows.';
COMMENT ON VIEW rbvm.current_network_reachability_evidence IS
    'Latest network reachability independently per tenant, asset, evidence source, origin, protocol, and endpoint. NOT_REACHABLE remains scoped negative evidence and is not a global-isolation claim.';
COMMENT ON VIEW rbvm.finding_network_reachability_evidence IS
    'Canonical findings joined by asset to zero or more current scoped reachability observations. Missing evidence remains NULL with network_reachability_observed=false.';

COMMIT;
