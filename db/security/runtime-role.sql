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
    rbvm.catalog_state,
    rbvm.public_intelligence_sync_run,
    rbvm.public_intelligence_sync_job
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
    rbvm.epss_evidence,
    rbvm.asset_context_snapshot,
    rbvm.asset_context_evidence,
    rbvm.network_reachability_snapshot,
    rbvm.network_reachability_evidence,
    rbvm.business_impact_snapshot,
    rbvm.business_impact_evidence,
    rbvm.decision_methodology_policy,
    rbvm.decision_methodology_evidence_policy,
    rbvm.decision_methodology_source_allowlist,
    rbvm.decision_input_snapshot,
    rbvm.decision_input_dimension,
    rbvm.decision_input_evidence_reference,
    rbvm.managed_asset,
    rbvm.managed_asset_revision,
    rbvm.scanner_managed_asset_link_event,
    rbvm.finding_reachability_scope_link_event,
    rbvm.finding_business_service_link_event,
    rbvm.formula_result,
    rbvm.derived_risk_result,
    rbvm.risk_method_selection_policy,
    rbvm.risk_method_selection_policy_activation_event,
    rbvm.active_risk_method_execution_binding,
    rbvm.finding_mvp_priority_result,
    rbvm.public_intelligence_record
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
    rbvm.finding_epss_evidence,
    rbvm.current_asset_context_evidence,
    rbvm.finding_asset_context_evidence,
    rbvm.current_network_reachability_evidence,
    rbvm.finding_network_reachability_evidence,
    rbvm.current_business_impact_evidence,
    rbvm.finding_business_impact_evidence,
    rbvm.current_managed_asset,
    rbvm.active_managed_asset,
    rbvm.current_scanner_managed_asset_link,
    rbvm.active_scanner_managed_asset_link,
    rbvm.current_finding_reachability_scope_link,
    rbvm.active_finding_reachability_scope_link,
    rbvm.current_finding_business_service_link,
    rbvm.active_finding_business_service_link,
    rbvm.current_risk_method_selection_policy_activation,
    rbvm.active_risk_method_selection_policy,
    rbvm.latest_public_intelligence_record,
    rbvm.current_public_intelligence_record,
    rbvm.public_intelligence_source_status,
    rbvm.public_intelligence_provider_status_v1
TO rbvm_runtime;

GRANT USAGE, SELECT ON SEQUENCE rbvm.case_audit_event_database_sequence TO rbvm_runtime;

REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.case_audit_event FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.applicability_assessment FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.cvss_v31_base_evidence FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.cisa_kev_catalog_snapshot FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.cisa_kev_evidence FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.epss_score_snapshot FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.epss_evidence FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.asset_context_snapshot FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.asset_context_evidence FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.network_reachability_snapshot FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.network_reachability_evidence FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.business_impact_snapshot FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.business_impact_evidence FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.decision_methodology_policy FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.decision_methodology_evidence_policy FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.decision_methodology_source_allowlist FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.decision_input_snapshot FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.decision_input_dimension FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.decision_input_evidence_reference FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.managed_asset FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.managed_asset_revision FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.scanner_managed_asset_link_event FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.finding_reachability_scope_link_event FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.finding_business_service_link_event FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.formula_result FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.derived_risk_result FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.risk_method_selection_policy FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.risk_method_selection_policy_activation_event FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.active_risk_method_execution_binding FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.finding_mvp_priority_result FROM rbvm_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.public_intelligence_record FROM rbvm_runtime;
REVOKE DELETE, TRUNCATE ON rbvm.public_intelligence_sync_run FROM rbvm_runtime;
REVOKE DELETE, TRUNCATE ON rbvm.public_intelligence_sync_job FROM rbvm_runtime;
