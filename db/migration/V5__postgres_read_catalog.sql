BEGIN;

CREATE INDEX vulnerability_case_catalog_order_idx
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

CREATE INDEX vulnerability_case_status_filter_idx
    ON rbvm.vulnerability_case (tenant_id, status, current_severity, last_observed_at DESC);

CREATE INDEX exposure_case_catalog_order_idx
    ON rbvm.exposure (
        tenant_id,
        case_id,
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

CREATE INDEX asset_name_search_idx
    ON rbvm.asset (tenant_id, lower(observed_name) text_pattern_ops);

CREATE OR REPLACE FUNCTION rbvm.reject_case_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'rbvm.case_audit_event is append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER case_audit_event_append_only
BEFORE UPDATE OR DELETE ON rbvm.case_audit_event
FOR EACH ROW EXECUTE FUNCTION rbvm.reject_case_audit_event_mutation();

COMMENT ON TRIGGER case_audit_event_append_only ON rbvm.case_audit_event IS
    'Increment 6 database-level guard: audit events are immutable after insert.';

COMMIT;
