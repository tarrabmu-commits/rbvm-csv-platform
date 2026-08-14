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
    rbvm.domain_materialization
TO rbvm_runtime;

GRANT SELECT ON
    rbvm.schema_migration,
    rbvm.case_dashboard,
    rbvm.import_reconciliation,
    rbvm.case_workflow_reconciliation,
    rbvm.postgres_projection_reconciliation
TO rbvm_runtime;

GRANT USAGE, SELECT ON SEQUENCE rbvm.case_audit_event_database_sequence TO rbvm_runtime;

REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.case_audit_event FROM rbvm_runtime;
