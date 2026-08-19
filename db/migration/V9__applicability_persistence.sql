BEGIN;

-- Applicability is finding-scoped evidence. The persistent Finding_ID is the
-- tenant-scoped rbvm.exposure.id UUID because exposure already represents the
-- canonical Asset + CVE + Component + Source Profile finding grain.
CREATE TABLE rbvm.applicability_assessment (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('APPLICABLE', 'NOT_APPLICABLE', 'UNKNOWN')),
    reason text NOT NULL CHECK (length(trim(reason)) > 0),
    evidence_source text NOT NULL CHECK (length(trim(evidence_source)) > 0),
    evaluated_at timestamptz NOT NULL,
    ingested_at timestamptz NOT NULL,
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    UNIQUE (tenant_id, id),
    CONSTRAINT applicability_one_assessment_time
        UNIQUE (tenant_id, finding_id, evaluated_at),
    FOREIGN KEY (tenant_id, finding_id)
        REFERENCES rbvm.exposure(tenant_id, id)
);

CREATE INDEX applicability_assessment_finding_time_idx
    ON rbvm.applicability_assessment (tenant_id, finding_id, evaluated_at DESC, ingested_at DESC);

CREATE VIEW rbvm.current_applicability_assessment AS
SELECT DISTINCT ON (tenant_id, finding_id)
    id,
    tenant_id,
    finding_id,
    status,
    reason,
    evidence_source,
    evaluated_at,
    ingested_at,
    evidence_sha256
FROM rbvm.applicability_assessment
ORDER BY tenant_id, finding_id, evaluated_at DESC, ingested_at DESC, id DESC;

CREATE VIEW rbvm.finding_applicability AS
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
    f.current_severity,
    COALESCE(a.status, 'UNKNOWN') AS applicability_status,
    (a.id IS NOT NULL) AS applicability_assessed,
    a.reason AS applicability_reason,
    a.evidence_source AS applicability_evidence_source,
    a.evaluated_at AS applicability_evaluated_at,
    a.ingested_at AS applicability_ingested_at
FROM rbvm.operational_finding f
LEFT JOIN rbvm.current_applicability_assessment a
  ON a.tenant_id = f.tenant_id
 AND a.finding_id = f.exposure_id;

COMMENT ON TABLE rbvm.applicability_assessment IS
    'Immutable finding-scoped applicability history imported from APPLICABILITY_CSV_V1.';
COMMENT ON COLUMN rbvm.applicability_assessment.finding_id IS
    'Canonical Finding_ID. It is the tenant-scoped rbvm.exposure.id UUID.';
COMMENT ON CONSTRAINT applicability_one_assessment_time
    ON rbvm.applicability_assessment IS
    'At one evaluation timestamp a finding may have only one applicability conclusion; exact replay is handled idempotently by the importer and conflicting content is rejected.';
COMMENT ON VIEW rbvm.current_applicability_assessment IS
    'Latest explicit applicability assessment only. Findings with no assessment are intentionally absent from this view.';
COMMENT ON VIEW rbvm.finding_applicability IS
    'All canonical findings with current applicability. No explicit assessment is represented as UNKNOWN with applicability_assessed=false.';

COMMIT;
