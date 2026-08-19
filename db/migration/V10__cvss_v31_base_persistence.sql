BEGIN;

-- CVSS v3.1 Base is CVE-scoped technical-severity evidence. It is persisted
-- independently from Wazuh findings, applicability, EPSS, KEV, and local
-- priority policy. Tenant scope protects multi-tenant reads/imports without
-- changing the intrinsic CVE grain of the evidence itself.
CREATE TABLE rbvm.cvss_v31_base_evidence (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    cvss_version text NOT NULL CHECK (cvss_version = '3.1'),
    base_score numeric(3,1) NOT NULL CHECK (base_score BETWEEN 0.0 AND 10.0),
    vector text NOT NULL CHECK (vector LIKE 'CVSS:3.1/%'),
    cvss_source text NOT NULL CHECK (
        length(trim(cvss_source)) > 0
        AND cvss_source ~* '^https://[^[:space:]]+$'
    ),
    observed_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL,
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    UNIQUE (tenant_id, id),
    CONSTRAINT cvss_v31_one_source_observation
        UNIQUE (tenant_id, vulnerability_id, cvss_source, observed_at),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id),
    FOREIGN KEY (vulnerability_id) REFERENCES rbvm.vulnerability(id)
);

CREATE INDEX cvss_v31_base_evidence_lookup_idx
    ON rbvm.cvss_v31_base_evidence
       (tenant_id, vulnerability_id, cvss_source, observed_at DESC, ingested_at DESC);

-- "Current" is deliberately per source. If two trusted sources disagree, this
-- layer preserves both instead of silently choosing a winner by recency.
CREATE VIEW rbvm.current_cvss_v31_base_evidence AS
SELECT DISTINCT ON (tenant_id, vulnerability_id, cvss_source)
    id,
    tenant_id,
    vulnerability_id,
    cvss_version,
    base_score,
    vector,
    cvss_source,
    observed_at,
    ingested_at,
    evidence_sha256
FROM rbvm.cvss_v31_base_evidence
ORDER BY tenant_id, vulnerability_id, cvss_source,
         observed_at DESC, ingested_at DESC, id DESC;

-- A canonical finding inherits zero or more current CVSS source observations
-- through its CVE. This remains a one-to-many evidence view and therefore does
-- not create an implicit source-precedence or risk-priority decision.
CREATE VIEW rbvm.finding_cvss_v31_base_evidence AS
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
    c.id AS cvss_evidence_id,
    c.cvss_version,
    c.base_score AS cvss_base_score,
    c.vector AS cvss_vector,
    c.cvss_source,
    c.observed_at AS cvss_observed_at,
    c.ingested_at AS cvss_ingested_at
FROM rbvm.operational_finding f
LEFT JOIN rbvm.current_cvss_v31_base_evidence c
  ON c.tenant_id = f.tenant_id
 AND c.vulnerability_id = f.vulnerability_id;

COMMENT ON TABLE rbvm.cvss_v31_base_evidence IS
    'Immutable tenant-scoped history of CVE-scoped CVSS v3.1 Base technical-severity evidence imported from CVSS_V31_CSV_V1 or an equivalent trusted source adapter.';
COMMENT ON CONSTRAINT cvss_v31_one_source_observation
    ON rbvm.cvss_v31_base_evidence IS
    'One source may provide only one CVSS v3.1 Base evidence record for a CVE at one observation timestamp; exact replay is idempotent and conflicting content must be rejected by the importer.';
COMMENT ON VIEW rbvm.current_cvss_v31_base_evidence IS
    'Latest CVSS v3.1 Base evidence independently for each tenant, CVE, and source. It does not arbitrate between sources.';
COMMENT ON VIEW rbvm.finding_cvss_v31_base_evidence IS
    'Canonical findings joined to current CVSS v3.1 Base evidence by tenant and CVE. Multiple source rows may exist and no priority or risk decision is implied.';

COMMIT;
