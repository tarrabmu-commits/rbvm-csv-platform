BEGIN;

CREATE TABLE rbvm.finding_mvp_priority_result (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    import_id uuid NOT NULL,
    csv_run_id uuid NOT NULL,
    analysis_id uuid NOT NULL,
    method_id text NOT NULL CHECK (method_id = 'RBVM_MVP_PRIORITY_POLICY_V1'),
    method_version integer NOT NULL CHECK (method_version = 1),
    method_sha256 char(64) NOT NULL CHECK (
        method_sha256 = '88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388'
    ),
    source_csv_sha256 char(64) NOT NULL CHECK (source_csv_sha256 ~ '^[a-f0-9]{64}$'),
    priority_csv_sha256 char(64) NOT NULL CHECK (priority_csv_sha256 ~ '^[a-f0-9]{64}$'),
    result_sha256 char(64) NOT NULL CHECK (result_sha256 ~ '^[a-f0-9]{64}$'),
    priority_status text NOT NULL CHECK (
        priority_status IN ('RANKED_RELATIVE_ONLY', 'UNRANKABLE_MISSING_EVIDENCE')
    ),
    priority_front integer CHECK (priority_front > 0),
    dominated_by bigint CHECK (dominated_by >= 0),
    dominates bigint CHECK (dominates >= 0),
    blockers text NOT NULL,
    explanation text NOT NULL CHECK (length(trim(explanation)) > 0),
    kev_listed boolean,
    internet_facing text CHECK (internet_facing IS NULL OR internet_facing IN ('YES', 'NO')),
    asset_criticality text CHECK (
        asset_criticality IS NULL OR asset_criticality IN ('LOW', 'MODERATE', 'HIGH', 'MISSION_CRITICAL')
    ),
    epss_probability numeric CHECK (
        epss_probability IS NULL OR (epss_probability >= 0 AND epss_probability <= 1)
    ),
    contextual_cvss_v4 numeric CHECK (
        contextual_cvss_v4 IS NULL OR (contextual_cvss_v4 >= 0 AND contextual_cvss_v4 <= 10)
    ),
    source_row_numbers bigint[] NOT NULL CHECK (
        cardinality(source_row_numbers) >= 1 AND source_row_numbers[1] >= 2
    ),
    materialized_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (
        tenant_id,
        finding_id,
        import_id,
        csv_run_id,
        analysis_id,
        method_sha256
    ),
    UNIQUE (tenant_id, result_sha256),
    FOREIGN KEY (tenant_id, finding_id) REFERENCES rbvm.exposure(tenant_id, id),
    FOREIGN KEY (tenant_id, import_id) REFERENCES rbvm.import_run(tenant_id, id),
    CHECK (
        (priority_status = 'RANKED_RELATIVE_ONLY'
            AND priority_front IS NOT NULL
            AND dominated_by IS NOT NULL
            AND dominates IS NOT NULL
            AND blockers = ''
            AND kev_listed IS NOT NULL
            AND internet_facing IS NOT NULL
            AND asset_criticality IS NOT NULL
            AND epss_probability IS NOT NULL
            AND contextual_cvss_v4 IS NOT NULL)
        OR
        (priority_status = 'UNRANKABLE_MISSING_EVIDENCE'
            AND priority_front IS NULL
            AND dominated_by IS NULL
            AND dominates IS NULL
            AND length(trim(blockers)) > 0)
    )
);

CREATE INDEX finding_mvp_priority_latest_idx
    ON rbvm.finding_mvp_priority_result (
        tenant_id,
        finding_id,
        materialized_at DESC,
        id DESC
    );

CREATE INDEX finding_mvp_priority_analysis_idx
    ON rbvm.finding_mvp_priority_result (
        tenant_id,
        csv_run_id,
        analysis_id,
        method_sha256
    );

COMMENT ON TABLE rbvm.finding_mvp_priority_result IS
    'Append-only materialization of frozen RBVM_MVP_PRIORITY_POLICY_V1 output onto exact canonical Findings through import_observation -> observation -> exposure lineage.';
COMMENT ON COLUMN rbvm.finding_mvp_priority_result.source_csv_sha256 IS
    'Must equal the exact canonical import_run.file_sha256; prevents cross-file or inferred Finding association.';
COMMENT ON COLUMN rbvm.finding_mvp_priority_result.kev_listed IS
    'Artifact-bound admitted priority input copied from immutable CSV-first analysis. It is provenance for this result, not a new canonical KEV evidence record.';
COMMENT ON COLUMN rbvm.finding_mvp_priority_result.internet_facing IS
    'Artifact-bound customer asset context. Internet Facing remains coarse context and is not exact Finding reachability or CVSS MAV.';
COMMENT ON COLUMN rbvm.finding_mvp_priority_result.contextual_cvss_v4 IS
    'Artifact-bound contextual CVSS v4 technical-severity input; it is not Organizational Risk.';
COMMENT ON COLUMN rbvm.finding_mvp_priority_result.priority_front IS
    'Relative Pareto front within the exact immutable input set; Front 1 is not Critical Risk, SLA, or Organizational Risk.';

CREATE FUNCTION rbvm.forbid_finding_mvp_priority_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'finding_mvp_priority_result is append-only';
END;
$$;

CREATE TRIGGER finding_mvp_priority_result_append_only
BEFORE UPDATE OR DELETE ON rbvm.finding_mvp_priority_result
FOR EACH ROW EXECUTE FUNCTION rbvm.forbid_finding_mvp_priority_mutation();

COMMIT;
