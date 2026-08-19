DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rbvm_runtime') THEN
        CREATE ROLE rbvm_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END;
$$;

GRANT CONNECT ON DATABASE rbvm TO rbvm_runtime;
GRANT USAGE ON SCHEMA rbvm TO rbvm_runtime;

GRANT SELECT, INSERT, UPDATE ON
    rbvm.tenant,
    rbvm.source_profile,
    rbvm.import_run,
    rbvm.asset,
    rbvm.vulnerability,
    rbvm.asset_component,
    rbvm.vulnerability_case,
    rbvm.exposure,
    rbvm.catalog_state
TO rbvm_runtime;

GRANT SELECT, INSERT ON
    rbvm.api_idempotency_key,
    rbvm.observation,
    rbvm.import_observation,
    rbvm.observation_reference,
    rbvm.exposure_observation,
    rbvm.validation_issue,
    rbvm.case_audit_event,
    rbvm.domain_materialization,
    rbvm.applicability_assessment,
    rbvm.cvss_v31_base_evidence,
    rbvm.cisa_kev_catalog_snapshot,
    rbvm.cisa_kev_evidence,
    rbvm.epss_score_snapshot,
    rbvm.epss_evidence
TO rbvm_runtime;

GRANT SELECT ON
    rbvm.schema_migration,
    rbvm.case_dashboard,
    rbvm.import_reconciliation,
    rbvm.case_workflow_reconciliation,
    rbvm.postgres_projection_reconciliation,
    rbvm.operational_finding,
    rbvm.analytics_overview,
    rbvm.analytics_severity_distribution,
    rbvm.analytics_asset_severity,
    rbvm.analytics_product_severity,
    rbvm.analytics_age_distribution,
    rbvm.analytics_asset_age,
    rbvm.finding_lifecycle_event,
    rbvm.analytics_lifecycle_daily,
    rbvm.analytics_lifecycle_weekly,
    rbvm.current_applicability_assessment,
    rbvm.finding_applicability,
    rbvm.current_cvss_v31_base_evidence,
    rbvm.finding_cvss_v31_base_evidence,
    rbvm.current_cisa_kev_evidence,
    rbvm.finding_cisa_kev_evidence,
    rbvm.current_epss_evidence,
    rbvm.finding_epss_evidence
TO rbvm_runtime;

GRANT USAGE, SELECT ON SEQUENCE rbvm.case_audit_event_database_sequence TO rbvm_runtime;

REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.case_audit_event FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.applicability_assessment FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.cvss_v31_base_evidence FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.cisa_kev_catalog_snapshot FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.cisa_kev_evidence FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.epss_score_snapshot FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.epss_evidence FROM rbvm_runtime;
