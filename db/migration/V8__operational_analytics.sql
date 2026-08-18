BEGIN;

-- Operational vulnerability-management analytics derived from canonical evidence.
-- These views deliberately do not implement an RBVM score, threat priority, or SLA policy.

CREATE VIEW rbvm.operational_finding AS
WITH base AS (
    SELECT
        e.tenant_id,
        e.id AS exposure_id,
        e.case_id,
        e.source_profile_id,
        sp.contract_id AS source_contract_id,
        (sp.contract_id = 'WAZUH_CSV_V2') AS lifecycle_evidence_explicit,
        e.asset_id,
        a.observed_name AS asset_name,
        a.source_asset_id,
        a.os_name_raw,
        e.vulnerability_id,
        v.cve_id,
        e.component_id,
        ac.observed_product_name AS product_name,
        ac.normalized_product_name,
        ac.package_version,
        ac.package_architecture,
        CASE
            WHEN sp.contract_id = 'WAZUH_CSV_V1' THEN 'OBSERVED_ONLY'
            ELSE e.status
        END AS evidence_state,
        c.status AS case_status,
        e.current_severity,
        e.first_observed_at,
        e.last_observed_at,
        e.lifecycle_observed_at,
        e.resolved_at,
        e.observation_count,
        e.severity_changed,
        e.timestamp_severity_conflict,
        CASE
            WHEN e.status = 'RESOLVED' AND e.resolved_at IS NOT NULL
                THEN GREATEST(0, e.resolved_at::date - e.first_observed_at::date)::bigint
            ELSE GREATEST(0, CURRENT_DATE - e.first_observed_at::date)::bigint
        END AS finding_age_days,
        CASE
            WHEN sp.contract_id = 'WAZUH_CSV_V2'
                 AND e.status = 'RESOLVED'
                 AND e.resolved_at IS NOT NULL
                THEN GREATEST(0, e.resolved_at::date - e.first_observed_at::date)::bigint
            ELSE NULL
        END AS time_to_resolution_days
    FROM rbvm.exposure e
    JOIN rbvm.source_profile sp
      ON sp.tenant_id = e.tenant_id AND sp.id = e.source_profile_id
    JOIN rbvm.asset a
      ON a.tenant_id = e.tenant_id AND a.id = e.asset_id
    JOIN rbvm.vulnerability v
      ON v.id = e.vulnerability_id
    JOIN rbvm.asset_component ac
      ON ac.tenant_id = e.tenant_id AND ac.id = e.component_id
    JOIN rbvm.vulnerability_case c
      ON c.tenant_id = e.tenant_id AND c.id = e.case_id
)
SELECT
    base.*,
    CASE
        WHEN finding_age_days <= 7 THEN '0-7 days'
        WHEN finding_age_days <= 30 THEN '8-30 days'
        WHEN finding_age_days <= 90 THEN '31-90 days'
        WHEN finding_age_days <= 180 THEN '91-180 days'
        ELSE '180+ days'
    END AS age_bucket
FROM base;

COMMENT ON VIEW rbvm.operational_finding IS
    'Evidence-safe finding view. WAZUH_CSV_V1 is OBSERVED_ONLY; missing later rows never imply resolution.';

CREATE VIEW rbvm.analytics_overview AS
SELECT
    tenant_id,
    count(*) AS finding_count,
    count(DISTINCT cve_id) AS unique_cves,
    count(DISTINCT asset_id) AS asset_count,
    count(DISTINCT component_id) AS component_count,
    count(*) FILTER (WHERE evidence_state = 'OBSERVED_ONLY') AS observed_only_findings,
    count(*) FILTER (WHERE evidence_state = 'ACTIVE') AS active_findings,
    count(*) FILTER (WHERE evidence_state = 'RESOLVED') AS resolved_findings,
    COALESCE(sum(observation_count), 0)::bigint AS observation_count,
    count(*) FILTER (WHERE severity_changed) AS findings_with_severity_changes,
    count(*) FILTER (WHERE timestamp_severity_conflict) AS findings_with_timestamp_conflicts
FROM rbvm.operational_finding
GROUP BY tenant_id;

CREATE VIEW rbvm.analytics_severity_distribution AS
SELECT
    tenant_id,
    evidence_state,
    current_severity,
    count(*) AS finding_count,
    count(DISTINCT cve_id) AS unique_cves,
    COALESCE(sum(observation_count), 0)::bigint AS observation_count
FROM rbvm.operational_finding
GROUP BY tenant_id, evidence_state, current_severity;

CREATE VIEW rbvm.analytics_asset_severity AS
SELECT
    tenant_id,
    asset_id,
    asset_name,
    source_asset_id,
    os_name_raw,
    evidence_state,
    current_severity,
    count(*) AS finding_count,
    count(DISTINCT cve_id) AS unique_cves,
    COALESCE(sum(observation_count), 0)::bigint AS observation_count
FROM rbvm.operational_finding
GROUP BY
    tenant_id,
    asset_id,
    asset_name,
    source_asset_id,
    os_name_raw,
    evidence_state,
    current_severity;

CREATE VIEW rbvm.analytics_product_severity AS
SELECT
    tenant_id,
    normalized_product_name,
    min(product_name) AS product_name,
    package_version,
    package_architecture,
    evidence_state,
    current_severity,
    count(*) AS finding_count,
    count(DISTINCT cve_id) AS unique_cves,
    count(DISTINCT asset_id) AS affected_assets,
    COALESCE(sum(observation_count), 0)::bigint AS observation_count
FROM rbvm.operational_finding
GROUP BY
    tenant_id,
    normalized_product_name,
    package_version,
    package_architecture,
    evidence_state,
    current_severity;

CREATE VIEW rbvm.analytics_age_distribution AS
SELECT
    tenant_id,
    evidence_state,
    age_bucket,
    count(*) AS finding_count
FROM rbvm.operational_finding
GROUP BY tenant_id, evidence_state, age_bucket;

CREATE VIEW rbvm.analytics_asset_age AS
SELECT
    tenant_id,
    asset_id,
    asset_name,
    source_asset_id,
    os_name_raw,
    count(*) AS current_finding_count,
    max(finding_age_days) AS max_finding_age_days,
    round(avg(finding_age_days), 2) AS average_finding_age_days,
    round(
        percentile_cont(0.5) WITHIN GROUP (ORDER BY finding_age_days)::numeric,
        2
    ) AS median_finding_age_days
FROM rbvm.operational_finding
WHERE evidence_state IN ('OBSERVED_ONLY', 'ACTIVE')
GROUP BY tenant_id, asset_id, asset_name, source_asset_id, os_name_raw;

-- Build lifecycle transitions only from explicit WAZUH_CSV_V2 evidence.
-- Equal-time conflicts collapse to ACTIVE, matching the conservative source-state rule.
CREATE VIEW rbvm.finding_lifecycle_event AS
WITH raw_evidence AS (
    SELECT
        eo.tenant_id,
        eo.exposure_id,
        COALESCE(o.resolved_at, o.detected_at) AS evidence_at,
        o.finding_status
    FROM rbvm.exposure_observation eo
    JOIN rbvm.observation o
      ON o.tenant_id = eo.tenant_id AND o.id = eo.observation_id
    JOIN rbvm.exposure e
      ON e.tenant_id = eo.tenant_id AND e.id = eo.exposure_id
    JOIN rbvm.source_profile sp
      ON sp.tenant_id = e.tenant_id AND sp.id = e.source_profile_id
    WHERE sp.contract_id = 'WAZUH_CSV_V2'
),
collapsed AS (
    SELECT
        tenant_id,
        exposure_id,
        evidence_at,
        CASE
            WHEN bool_or(finding_status = 'ACTIVE') THEN 'ACTIVE'
            ELSE 'RESOLVED'
        END AS evidence_state
    FROM raw_evidence
    GROUP BY tenant_id, exposure_id, evidence_at
),
ordered AS (
    SELECT
        tenant_id,
        exposure_id,
        evidence_at,
        evidence_state,
        lag(evidence_state) OVER (
            PARTITION BY tenant_id, exposure_id
            ORDER BY evidence_at
        ) AS previous_state
    FROM collapsed
),
transitions AS (
    SELECT
        tenant_id,
        exposure_id,
        evidence_at,
        evidence_state,
        previous_state,
        CASE
            WHEN previous_state IS NULL AND evidence_state = 'ACTIVE' THEN 'DETECTED'
            WHEN previous_state IS NULL AND evidence_state = 'RESOLVED'
                THEN 'RESOLVED_INITIAL_EVIDENCE'
            WHEN previous_state = 'RESOLVED' AND evidence_state = 'ACTIVE' THEN 'REOPENED'
            WHEN previous_state = 'ACTIVE' AND evidence_state = 'RESOLVED' THEN 'RESOLVED'
            ELSE NULL
        END AS event_type
    FROM ordered
)
SELECT
    t.tenant_id,
    t.exposure_id,
    f.case_id,
    f.asset_id,
    f.asset_name,
    f.vulnerability_id,
    f.cve_id,
    f.component_id,
    f.product_name,
    t.evidence_at AS event_at,
    t.event_type,
    t.previous_state,
    t.evidence_state AS resulting_state
FROM transitions t
JOIN rbvm.operational_finding f
  ON f.tenant_id = t.tenant_id AND f.exposure_id = t.exposure_id
WHERE t.event_type IS NOT NULL;

CREATE VIEW rbvm.analytics_lifecycle_daily AS
SELECT
    tenant_id,
    event_at::date AS event_date,
    event_type,
    count(*) AS finding_events
FROM rbvm.finding_lifecycle_event
GROUP BY tenant_id, event_at::date, event_type;

CREATE VIEW rbvm.analytics_lifecycle_weekly AS
SELECT
    tenant_id,
    date_trunc('week', event_at)::date AS week_start,
    event_type,
    count(*) AS finding_events
FROM rbvm.finding_lifecycle_event
GROUP BY tenant_id, date_trunc('week', event_at)::date, event_type;

COMMENT ON VIEW rbvm.finding_lifecycle_event IS
    'Lifecycle events derived only from explicit V2 evidence. No event is created from snapshot absence.';

COMMIT;
