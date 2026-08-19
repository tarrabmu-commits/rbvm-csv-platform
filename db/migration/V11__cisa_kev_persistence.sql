BEGIN;

-- CISA KEV is CVE-scoped threat evidence. Snapshot provenance is persisted
-- separately from membership results so LISTED and NOT_LISTED evidence remain
-- auditable against the exact validated catalog observation that produced them.
-- Tenant scope preserves isolation while retaining CVE-level evidence semantics.
CREATE TABLE rbvm.cisa_kev_catalog_snapshot (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    catalog_version text NOT NULL CHECK (length(trim(catalog_version)) > 0),
    catalog_sha256 char(64) NOT NULL CHECK (catalog_sha256 ~ '^[a-f0-9]{64}$'),
    catalog_count integer NOT NULL CHECK (catalog_count > 0),
    kev_source text NOT NULL CHECK (
        length(trim(kev_source)) > 0
        AND kev_source ~* '^https://[^[:space:]]+$'
    ),
    observed_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    CONSTRAINT cisa_kev_one_source_observation
        UNIQUE (tenant_id, kev_source, observed_at),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id)
);

CREATE INDEX cisa_kev_catalog_snapshot_lookup_idx
    ON rbvm.cisa_kev_catalog_snapshot
       (tenant_id, kev_source, observed_at DESC, ingested_at DESC);

CREATE TABLE rbvm.cisa_kev_evidence (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    kev_status text NOT NULL CHECK (kev_status IN ('LISTED', 'NOT_LISTED')),
    kev_date_added date,
    kev_due_date date,
    known_ransomware_campaign_use text,
    ingested_at timestamptz NOT NULL,
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    UNIQUE (tenant_id, id),
    CONSTRAINT cisa_kev_one_cve_per_snapshot
        UNIQUE (tenant_id, vulnerability_id, snapshot_id),
    FOREIGN KEY (tenant_id, snapshot_id)
        REFERENCES rbvm.cisa_kev_catalog_snapshot(tenant_id, id),
    FOREIGN KEY (vulnerability_id) REFERENCES rbvm.vulnerability(id),
    CONSTRAINT cisa_kev_listing_metadata_matches_status CHECK (
        (
            kev_status = 'LISTED'
            AND kev_date_added IS NOT NULL
            AND kev_due_date IS NOT NULL
            AND known_ransomware_campaign_use IN ('KNOWN', 'UNKNOWN')
        )
        OR
        (
            kev_status = 'NOT_LISTED'
            AND kev_date_added IS NULL
            AND kev_due_date IS NULL
            AND known_ransomware_campaign_use IS NULL
        )
    )
);

CREATE INDEX cisa_kev_evidence_lookup_idx
    ON rbvm.cisa_kev_evidence
       (tenant_id, vulnerability_id, snapshot_id, ingested_at DESC);

-- Current state remains per source. The official source adapter currently emits
-- one pinned CISA feed, but persistence does not silently arbitrate if another
-- provenance-equivalent CISA source is introduced later.
CREATE VIEW rbvm.current_cisa_kev_evidence AS
SELECT DISTINCT ON (e.tenant_id, e.vulnerability_id, s.kev_source)
    e.id,
    e.tenant_id,
    e.vulnerability_id,
    e.snapshot_id,
    e.kev_status,
    e.kev_date_added,
    e.kev_due_date,
    e.known_ransomware_campaign_use,
    e.ingested_at AS evidence_ingested_at,
    e.evidence_sha256,
    s.catalog_version,
    s.catalog_sha256,
    s.catalog_count,
    s.kev_source,
    s.observed_at,
    s.ingested_at AS snapshot_ingested_at
FROM rbvm.cisa_kev_evidence e
JOIN rbvm.cisa_kev_catalog_snapshot s
  ON s.tenant_id = e.tenant_id
 AND s.id = e.snapshot_id
ORDER BY e.tenant_id, e.vulnerability_id, s.kev_source,
         s.observed_at DESC, e.ingested_at DESC, e.id DESC;

-- Findings inherit KEV evidence by CVE. No explicit KEV evidence is represented
-- as UNKNOWN with kev_evidence_observed=false; UNKNOWN is never persisted as a
-- fabricated membership row.
CREATE VIEW rbvm.finding_cisa_kev_evidence AS
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
    COALESCE(k.kev_status, 'UNKNOWN') AS kev_status,
    (k.id IS NOT NULL) AS kev_evidence_observed,
    k.kev_date_added,
    k.kev_due_date,
    k.known_ransomware_campaign_use,
    k.catalog_version AS kev_catalog_version,
    k.catalog_sha256 AS kev_catalog_sha256,
    k.catalog_count AS kev_catalog_count,
    k.kev_source,
    k.observed_at AS kev_observed_at,
    k.evidence_ingested_at AS kev_evidence_ingested_at,
    k.snapshot_ingested_at AS kev_snapshot_ingested_at
FROM rbvm.operational_finding f
LEFT JOIN rbvm.current_cisa_kev_evidence k
  ON k.tenant_id = f.tenant_id
 AND k.vulnerability_id = f.vulnerability_id;

COMMENT ON TABLE rbvm.cisa_kev_catalog_snapshot IS
    'Immutable tenant-scoped provenance for validated complete CISA KEV catalog observations. Same source and observation time may identify only one snapshot.';
COMMENT ON CONSTRAINT cisa_kev_one_source_observation
    ON rbvm.cisa_kev_catalog_snapshot IS
    'At one observation timestamp a KEV source may identify only one exact catalog snapshot; replay/conflict handling is performed by the importer.';
COMMENT ON TABLE rbvm.cisa_kev_evidence IS
    'Immutable CVE-scoped LISTED or NOT_LISTED membership history bound by foreign key to a validated CISA KEV snapshot. UNKNOWN is represented by absence of evidence.';
COMMENT ON CONSTRAINT cisa_kev_listing_metadata_matches_status
    ON rbvm.cisa_kev_evidence IS
    'LISTED requires CISA listing metadata; NOT_LISTED forbids listing-only metadata.';
COMMENT ON VIEW rbvm.current_cisa_kev_evidence IS
    'Latest CISA KEV membership evidence independently per tenant, CVE, and source. It does not derive priority, risk, EPSS, or SLA.';
COMMENT ON VIEW rbvm.finding_cisa_kev_evidence IS
    'Canonical findings joined to current KEV evidence by tenant and CVE. Missing evidence appears as UNKNOWN without fabricating a KEV observation.';

COMMIT;
