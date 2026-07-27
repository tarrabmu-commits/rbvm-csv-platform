BEGIN;

ALTER TABLE rbvm.asset
    ADD COLUMN public_id char(64),
    ADD CONSTRAINT asset_public_id_required
        CHECK (public_id IS NOT NULL AND public_id ~ '^[a-f0-9]{64}$') NOT VALID;
ALTER TABLE rbvm.asset_component
    ADD COLUMN public_id char(64),
    ADD CONSTRAINT asset_component_public_id_required
        CHECK (public_id IS NOT NULL AND public_id ~ '^[a-f0-9]{64}$') NOT VALID;
ALTER TABLE rbvm.vulnerability_case
    ADD COLUMN public_id char(64),
    ADD CONSTRAINT vulnerability_case_public_id_required
        CHECK (public_id IS NOT NULL AND public_id ~ '^[a-f0-9]{64}$') NOT VALID;
ALTER TABLE rbvm.exposure
    ADD COLUMN public_id char(64),
    ADD CONSTRAINT exposure_public_id_required
        CHECK (public_id IS NOT NULL AND public_id ~ '^[a-f0-9]{64}$') NOT VALID;
ALTER TABLE rbvm.case_audit_event
    ADD COLUMN public_id char(64),
    ADD COLUMN source_sequence bigint,
    ADD CONSTRAINT case_audit_event_public_id_required
        CHECK (public_id IS NOT NULL AND public_id ~ '^[a-f0-9]{64}$') NOT VALID,
    ADD CONSTRAINT case_audit_event_source_sequence_required
        CHECK (source_sequence IS NOT NULL AND source_sequence > 0) NOT VALID;

CREATE UNIQUE INDEX asset_public_id_idx
    ON rbvm.asset (tenant_id, public_id) WHERE public_id IS NOT NULL;
CREATE UNIQUE INDEX asset_component_public_id_idx
    ON rbvm.asset_component (tenant_id, public_id) WHERE public_id IS NOT NULL;
CREATE UNIQUE INDEX vulnerability_case_public_id_idx
    ON rbvm.vulnerability_case (tenant_id, public_id) WHERE public_id IS NOT NULL;
CREATE UNIQUE INDEX exposure_public_id_idx
    ON rbvm.exposure (tenant_id, public_id) WHERE public_id IS NOT NULL;
CREATE UNIQUE INDEX case_audit_event_public_id_idx
    ON rbvm.case_audit_event (tenant_id, public_id) WHERE public_id IS NOT NULL;

ALTER TABLE rbvm.vulnerability
    ADD COLUMN description_current text NOT NULL DEFAULT '',
    ADD COLUMN description_observed_at timestamptz;

CREATE SEQUENCE rbvm.case_audit_event_database_sequence;
SELECT setval(
    'rbvm.case_audit_event_database_sequence',
    COALESCE((SELECT max(sequence_number) FROM rbvm.case_audit_event), 0) + 1,
    false
);
ALTER TABLE rbvm.case_audit_event
    ALTER COLUMN sequence_number
        SET DEFAULT nextval('rbvm.case_audit_event_database_sequence');
ALTER SEQUENCE rbvm.case_audit_event_database_sequence
    OWNED BY rbvm.case_audit_event.sequence_number;

CREATE TABLE rbvm.domain_materialization (
    tenant_id uuid NOT NULL,
    import_id uuid NOT NULL,
    accepted_observations bigint NOT NULL CHECK (accepted_observations >= 0),
    inserted_observations bigint NOT NULL CHECK (inserted_observations >= 0),
    duplicate_observations bigint NOT NULL CHECK (duplicate_observations >= 0),
    new_assets bigint NOT NULL CHECK (new_assets >= 0),
    new_vulnerabilities bigint NOT NULL CHECK (new_vulnerabilities >= 0),
    new_components bigint NOT NULL CHECK (new_components >= 0),
    new_exposures bigint NOT NULL CHECK (new_exposures >= 0),
    updated_exposures bigint NOT NULL CHECK (updated_exposures >= 0),
    new_cases bigint NOT NULL CHECK (new_cases >= 0),
    updated_cases bigint NOT NULL CHECK (updated_cases >= 0),
    materialized_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, import_id),
    FOREIGN KEY (tenant_id, import_id) REFERENCES rbvm.import_run(tenant_id, id),
    CHECK (accepted_observations = inserted_observations + duplicate_observations)
);

CREATE TABLE rbvm.catalog_state (
    tenant_id uuid PRIMARY KEY,
    revision bigint NOT NULL CHECK (revision >= 0),
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id)
);

CREATE VIEW rbvm.postgres_projection_reconciliation AS
SELECT
    t.id AS tenant_id,
    (SELECT count(*) FROM rbvm.asset a
        WHERE a.tenant_id = t.id AND a.public_id IS NULL) AS assets_without_public_id,
    (SELECT count(*) FROM rbvm.asset_component ac
        WHERE ac.tenant_id = t.id AND ac.public_id IS NULL) AS components_without_public_id,
    (SELECT count(*) FROM rbvm.vulnerability_case c
        WHERE c.tenant_id = t.id AND c.public_id IS NULL) AS cases_without_public_id,
    (SELECT count(*) FROM rbvm.exposure e
        WHERE e.tenant_id = t.id AND e.public_id IS NULL) AS exposures_without_public_id,
    (SELECT count(*) FROM rbvm.case_audit_event ae
        WHERE ae.tenant_id = t.id AND ae.public_id IS NULL) AS audit_events_without_public_id,
    COALESCE((
        SELECT count(*)
        FROM rbvm.import_reconciliation ir
        WHERE ir.tenant_id = t.id AND ir.reconciliation_state <> 'RECONCILED'
    ), 0) AS unreconciled_imports,
    COALESCE((
        SELECT count(*)
        FROM rbvm.case_workflow_reconciliation wr
        WHERE wr.tenant_id = t.id AND wr.reconciliation_state <> 'RECONCILED'
    ), 0) AS unreconciled_case_workflows
FROM rbvm.tenant t;

COMMENT ON VIEW rbvm.postgres_projection_reconciliation IS
    'Operational checks for the optional PostgreSQL canonical projection.';
COMMENT ON CONSTRAINT asset_public_id_required ON rbvm.asset IS
    'NOT VALID permits upgrade inspection of legacy rows while enforcing IDs on new projection writes.';
COMMENT ON COLUMN rbvm.case_audit_event.source_sequence IS
    'Sequence from the local append-only event journal; sequence_number remains database-global.';

COMMIT;
