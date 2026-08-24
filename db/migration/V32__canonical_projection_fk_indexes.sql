BEGIN;

-- Canonical imports update parent entities while their evidence/link relations grow in the
-- same transaction. PostgreSQL foreign-key checks must be able to resolve every referencing
-- key directly; otherwise a large first import can repeatedly walk a broad tenant index and
-- produce super-linear write amplification.

-- observation -> asset_component(tenant_id, id)
CREATE INDEX observation_tenant_component_fk_idx
    ON rbvm.observation (tenant_id, component_id);

-- vulnerability_case -> asset(tenant_id, id) and vulnerability(id)
CREATE INDEX vulnerability_case_tenant_asset_fk_idx
    ON rbvm.vulnerability_case (tenant_id, asset_id);
CREATE INDEX vulnerability_case_vulnerability_fk_idx
    ON rbvm.vulnerability_case (vulnerability_id);

-- exposure -> asset/case/vulnerability/component. tenant+case already exists from V28.
CREATE INDEX exposure_tenant_asset_fk_idx
    ON rbvm.exposure (tenant_id, asset_id);
CREATE INDEX exposure_vulnerability_fk_idx
    ON rbvm.exposure (vulnerability_id);
CREATE INDEX exposure_tenant_component_fk_idx
    ON rbvm.exposure (tenant_id, component_id);

-- Reverse observation links: the primary keys are ordered by import/exposure first and cannot
-- efficiently support an RI lookup by observation_id.
CREATE INDEX import_observation_tenant_observation_fk_idx
    ON rbvm.import_observation (tenant_id, observation_id);
CREATE INDEX exposure_observation_tenant_observation_fk_idx
    ON rbvm.exposure_observation (tenant_id, observation_id);

COMMIT;
