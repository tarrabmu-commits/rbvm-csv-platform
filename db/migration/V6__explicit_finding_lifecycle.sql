BEGIN;

ALTER TABLE rbvm.source_profile DROP CONSTRAINT source_profile_contract_id_check;
ALTER TABLE rbvm.source_profile DROP CONSTRAINT source_profile_semantics_check;
ALTER TABLE rbvm.source_profile ADD CONSTRAINT source_profile_contract_id_check
    CHECK (contract_id IN ('WAZUH_CSV_V1', 'WAZUH_CSV_V2'));
ALTER TABLE rbvm.source_profile ADD CONSTRAINT source_profile_semantics_check CHECK (
    (contract_id = 'WAZUH_CSV_V1' AND semantics = 'POSITIVE_OBSERVATION_EXPORT') OR
    (contract_id = 'WAZUH_CSV_V2' AND semantics = 'EXPLICIT_FINDING_LIFECYCLE_EXPORT')
);

ALTER TABLE rbvm.import_run DROP CONSTRAINT import_run_contract_id_check;
ALTER TABLE rbvm.import_run DROP CONSTRAINT import_run_semantics_check;
ALTER TABLE rbvm.import_run ADD CONSTRAINT import_run_contract_id_check
    CHECK (contract_id IN ('WAZUH_CSV_V1', 'WAZUH_CSV_V2'));
ALTER TABLE rbvm.import_run ADD CONSTRAINT import_run_semantics_check CHECK (
    (contract_id = 'WAZUH_CSV_V1' AND semantics = 'POSITIVE_OBSERVATION_EXPORT') OR
    (contract_id = 'WAZUH_CSV_V2' AND semantics = 'EXPLICIT_FINDING_LIFECYCLE_EXPORT')
);

ALTER TABLE rbvm.asset DROP CONSTRAINT asset_identity_basis_check;
ALTER TABLE rbvm.asset DROP CONSTRAINT asset_identity_confidence_check;
ALTER TABLE rbvm.asset ADD COLUMN source_asset_id text;
ALTER TABLE rbvm.asset ADD CONSTRAINT asset_identity_basis_check
    CHECK (identity_basis IN ('SOURCE_NAME_ONLY', 'SOURCE_STABLE_ID'));
ALTER TABLE rbvm.asset ADD CONSTRAINT asset_identity_confidence_check
    CHECK (identity_confidence IN ('LOW', 'HIGH'));
ALTER TABLE rbvm.asset ADD CONSTRAINT asset_identity_evidence_check CHECK (
    (identity_basis = 'SOURCE_NAME_ONLY' AND identity_confidence = 'LOW'
        AND source_asset_id IS NULL) OR
    (identity_basis = 'SOURCE_STABLE_ID' AND identity_confidence = 'HIGH'
        AND source_asset_id IS NOT NULL AND length(trim(source_asset_id)) > 0)
);

ALTER TABLE rbvm.asset_component DROP CONSTRAINT asset_component_version_status_check;
ALTER TABLE rbvm.asset_component
    ADD COLUMN package_version text NOT NULL DEFAULT '',
    ADD COLUMN package_architecture text NOT NULL DEFAULT '';
ALTER TABLE rbvm.asset_component ADD CONSTRAINT asset_component_version_status_check
    CHECK (version_status IN ('UNKNOWN_FROM_SOURCE', 'OBSERVED_FROM_SOURCE'));
ALTER TABLE rbvm.asset_component ADD CONSTRAINT asset_component_version_evidence_check CHECK (
    (version_status = 'UNKNOWN_FROM_SOURCE' AND package_version = ''
        AND package_architecture = '') OR
    (version_status = 'OBSERVED_FROM_SOURCE' AND length(trim(package_version)) > 0
        AND length(trim(package_architecture)) > 0)
);

ALTER TABLE rbvm.observation
    ADD COLUMN finding_status text NOT NULL DEFAULT 'ACTIVE'
        CHECK (finding_status IN ('ACTIVE', 'RESOLVED')),
    ADD COLUMN resolved_at timestamptz;
ALTER TABLE rbvm.observation ADD CONSTRAINT observation_lifecycle_evidence_check CHECK (
    (finding_status = 'ACTIVE' AND resolved_at IS NULL) OR
    (finding_status = 'RESOLVED' AND resolved_at IS NOT NULL AND resolved_at >= detected_at)
);

ALTER TABLE rbvm.exposure DROP CONSTRAINT exposure_status_check;
ALTER TABLE rbvm.exposure DROP CONSTRAINT exposure_closure_policy_check;
ALTER TABLE rbvm.exposure
    ADD COLUMN lifecycle_observed_at timestamptz,
    ADD COLUMN resolved_at timestamptz;
UPDATE rbvm.exposure SET lifecycle_observed_at = last_observed_at;
UPDATE rbvm.exposure SET status = 'ACTIVE' WHERE status = 'OPEN';
ALTER TABLE rbvm.exposure ALTER COLUMN lifecycle_observed_at SET NOT NULL;
ALTER TABLE rbvm.exposure ADD CONSTRAINT exposure_status_check
    CHECK (status IN ('ACTIVE', 'RESOLVED'));
ALTER TABLE rbvm.exposure ADD CONSTRAINT exposure_closure_policy_check
    CHECK (closure_policy IN ('POSITIVE_ONLY_NO_AUTO_CLOSE', 'EXPLICIT_SOURCE_EVIDENCE_ONLY'));
ALTER TABLE rbvm.exposure ADD CONSTRAINT exposure_lifecycle_state_check CHECK (
    (status = 'ACTIVE' AND resolved_at IS NULL) OR
    (status = 'RESOLVED' AND resolved_at IS NOT NULL)
);
ALTER TABLE rbvm.vulnerability_case DROP CONSTRAINT vulnerability_case_status_check;
ALTER TABLE rbvm.vulnerability_case DROP CONSTRAINT vulnerability_case_closure_policy_check;
ALTER TABLE rbvm.vulnerability_case ADD CONSTRAINT vulnerability_case_status_check
    CHECK (status IN ('OPEN', 'SOURCE_RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'CLOSED_MANUAL'));
ALTER TABLE rbvm.vulnerability_case ADD CONSTRAINT vulnerability_case_closure_policy_check
    CHECK (closure_policy IN ('POSITIVE_ONLY_NO_AUTO_CLOSE', 'EXPLICIT_SOURCE_EVIDENCE_ONLY'));

DROP INDEX rbvm.exposure_open_severity_idx;
CREATE INDEX exposure_active_severity_idx
    ON rbvm.exposure (tenant_id, current_severity, last_observed_at DESC)
    WHERE status = 'ACTIVE';

COMMENT ON COLUMN rbvm.asset.source_asset_id IS
    'Stable source identity required by WAZUH_CSV_V2; V1 continues name-only identity.';
COMMENT ON COLUMN rbvm.observation.finding_status IS
    'Immutable explicit lifecycle evidence. Missing rows never imply resolution.';
COMMENT ON COLUMN rbvm.exposure.lifecycle_observed_at IS
    'Latest explicit ACTIVE or RESOLVED evidence time; ACTIVE wins an equal-time conflict.';

COMMIT;
