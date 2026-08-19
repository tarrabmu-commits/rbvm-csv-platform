BEGIN;

-- EPSS is CVE-scoped exploitation-probability evidence. Provenance for one
-- validated FIRST daily feed observation is persisted separately from the CVE
-- score rows so model version, score date, source bytes, and acquisition time
-- remain auditable without being reinterpreted as organizational risk.
CREATE TABLE rbvm.epss_score_snapshot (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    model_version text NOT NULL CHECK (
        model_version ~ '^v?[0-9]{4}\.[0-9]{2}\.[0-9]{2}$'
    ),
    score_date date NOT NULL,
    epss_source text NOT NULL CHECK (
        length(trim(epss_source)) > 0
        AND epss_source ~* '^https://[^[:space:]]+$'
    ),
    source_sha256 char(64) NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
    observed_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    CONSTRAINT epss_one_source_observation
        UNIQUE (tenant_id, epss_source, observed_at),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id)
);

CREATE INDEX epss_score_snapshot_lookup_idx
    ON rbvm.epss_score_snapshot
       (tenant_id, epss_source, score_date DESC, observed_at DESC, ingested_at DESC);

CREATE TABLE rbvm.epss_evidence (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    epss_probability numeric NOT NULL CHECK (
        epss_probability >= 0 AND epss_probability <= 1
    ),
    epss_percentile numeric NOT NULL CHECK (
        epss_percentile >= 0 AND epss_percentile <= 1
    ),
    ingested_at timestamptz NOT NULL,
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    UNIQUE (tenant_id, id),
    CONSTRAINT epss_one_cve_per_snapshot
        UNIQUE (tenant_id, vulnerability_id, snapshot_id),
    FOREIGN KEY (tenant_id, snapshot_id)
        REFERENCES rbvm.epss_score_snapshot(tenant_id, id),
    FOREIGN KEY (vulnerability_id) REFERENCES rbvm.vulnerability(id)
);

CREATE INDEX epss_evidence_lookup_idx
    ON rbvm.epss_evidence
       (tenant_id, vulnerability_id, snapshot_id, ingested_at DESC);

-- Current EPSS is latest by FIRST score publication date, not merely by local
-- acquisition time. This prevents a later offline replay of an older feed from
-- silently replacing a newer published score. Ties use observation/ingest time
-- deterministically. Current remains independent per source.
CREATE VIEW rbvm.current_epss_evidence AS
SELECT DISTINCT ON (e.tenant_id, e.vulnerability_id, s.epss_source)
    e.id,
    e.tenant_id,
    e.vulnerability_id,
    e.snapshot_id,
    e.epss_probability,
    e.epss_percentile,
    e.ingested_at AS evidence_ingested_at,
    e.evidence_sha256,
    s.model_version,
    s.score_date,
    s.epss_source,
    s.source_sha256,
    s.observed_at,
    s.ingested_at AS snapshot_ingested_at
FROM rbvm.epss_evidence e
JOIN rbvm.epss_score_snapshot s
  ON s.tenant_id = e.tenant_id
 AND s.id = e.snapshot_id
ORDER BY e.tenant_id, e.vulnerability_id, s.epss_source,
         s.score_date DESC, s.observed_at DESC, e.ingested_at DESC, e.id DESC;

-- Findings inherit zero or more current EPSS observations by CVE. A missing
-- score remains absence of usable EPSS evidence: probability and percentile are
-- NULL and epss_evidence_observed=false. No zero or fabricated UNKNOWN row is
-- persisted.
CREATE VIEW rbvm.finding_epss_evidence AS
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
    (e.id IS NOT NULL) AS epss_evidence_observed,
    e.epss_probability,
    e.epss_percentile,
    e.model_version AS epss_model_version,
    e.score_date AS epss_score_date,
    e.epss_source,
    e.source_sha256 AS epss_source_sha256,
    e.observed_at AS epss_observed_at,
    e.evidence_ingested_at AS epss_evidence_ingested_at,
    e.snapshot_ingested_at AS epss_snapshot_ingested_at
FROM rbvm.operational_finding f
LEFT JOIN rbvm.current_epss_evidence e
  ON e.tenant_id = f.tenant_id
 AND e.vulnerability_id = f.vulnerability_id;

COMMENT ON TABLE rbvm.epss_score_snapshot IS
    'Immutable tenant-scoped provenance for validated FIRST EPSS daily score-feed observations. Score date and local observation time remain separate.';
COMMENT ON CONSTRAINT epss_one_source_observation
    ON rbvm.epss_score_snapshot IS
    'At one observation timestamp an EPSS source may identify only one exact model/date/source-byte snapshot; replay/conflict handling is performed by the importer.';
COMMENT ON TABLE rbvm.epss_evidence IS
    'Immutable CVE-scoped EPSS probability and percentile history bound to validated score-feed provenance. Missing CVEs are represented by absence of evidence, never probability zero.';
COMMENT ON VIEW rbvm.current_epss_evidence IS
    'Latest published EPSS score independently per tenant, CVE, and source, ordered by score date before acquisition time. It does not derive priority, risk, SLA, CVSS/KEV combination, or asset context.';
COMMENT ON VIEW rbvm.finding_epss_evidence IS
    'Canonical findings joined to current EPSS evidence by tenant and CVE. Missing evidence remains NULL with epss_evidence_observed=false.';

COMMIT;
