BEGIN;

-- Findings pagination reads at most 100 cases, but each row also resolves its
-- exposure count. Without a tenant/case lookup index PostgreSQL can repeatedly
-- scan the full exposure relation for the correlated count subquery.
CREATE INDEX exposure_tenant_case_lookup_idx
    ON rbvm.exposure (tenant_id, case_id);

-- Match the default Findings ORDER BY expression so the first and subsequent
-- cursor pages do not require a large sort over the complete case relation.
CREATE INDEX case_findings_page_order_idx
    ON rbvm.vulnerability_case (
        tenant_id,
        (CASE current_severity
            WHEN 'CRITICAL' THEN 4
            WHEN 'HIGH' THEN 3
            WHEN 'MEDIUM' THEN 2
            WHEN 'LOW' THEN 1
            ELSE 0
        END) DESC,
        last_observed_at DESC,
        public_id
    );

-- Dedicated intelligence summary semantics are intentionally based on every
-- canonical observation. Support tenant-scoped DISTINCT vulnerability reads
-- without changing that evidence scope to the smaller case relation.
CREATE INDEX observation_tenant_vulnerability_lookup_idx
    ON rbvm.observation (tenant_id, vulnerability_id);

COMMIT;
