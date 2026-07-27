BEGIN;

CREATE VIEW rbvm.case_dashboard AS
SELECT
    c.tenant_id,
    c.id AS case_id,
    a.observed_name AS asset_name,
    v.cve_id,
    c.status,
    c.current_severity,
    c.first_observed_at,
    c.last_observed_at,
    count(e.id) AS exposure_count,
    sum(e.observation_count) AS observation_count,
    bool_or(e.severity_changed) AS has_severity_change,
    bool_or(e.timestamp_severity_conflict) AS has_timestamp_severity_conflict
FROM rbvm.vulnerability_case c
JOIN rbvm.asset a
  ON a.tenant_id = c.tenant_id AND a.id = c.asset_id
JOIN rbvm.vulnerability v
  ON v.id = c.vulnerability_id
JOIN rbvm.exposure e
  ON e.tenant_id = c.tenant_id AND e.case_id = c.id
GROUP BY
    c.tenant_id,
    c.id,
    a.observed_name,
    v.cve_id,
    c.status,
    c.current_severity,
    c.first_observed_at,
    c.last_observed_at;

CREATE VIEW rbvm.import_reconciliation AS
SELECT
    i.tenant_id,
    i.id AS import_id,
    i.status,
    i.logical_rows,
    i.accepted_rows,
    i.deduplicated_rows,
    i.quarantined_rows,
    count(io.observation_id) AS linked_observations,
    CASE
        WHEN i.status = 'COMPLETED' AND count(io.observation_id) <> COALESCE(i.accepted_rows, 0)
            THEN 'INVALID_LINK_COUNT'
        WHEN i.status = 'COMPLETED'
            THEN 'RECONCILED'
        ELSE 'NOT_TERMINAL'
    END AS reconciliation_state
FROM rbvm.import_run i
LEFT JOIN rbvm.import_observation io
  ON io.tenant_id = i.tenant_id AND io.import_id = i.id
GROUP BY
    i.tenant_id,
    i.id,
    i.status,
    i.logical_rows,
    i.accepted_rows,
    i.deduplicated_rows,
    i.quarantined_rows;

COMMIT;
