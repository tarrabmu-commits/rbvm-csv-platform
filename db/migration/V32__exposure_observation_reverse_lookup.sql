BEGIN;

-- Exact import -> observation -> Finding lineage reads start from observation_id.
-- The original PK is exposure-first, so add the reverse lookup shape explicitly.
CREATE INDEX exposure_observation_observation_lookup_idx
    ON rbvm.exposure_observation (tenant_id, observation_id, exposure_id);

COMMIT;
