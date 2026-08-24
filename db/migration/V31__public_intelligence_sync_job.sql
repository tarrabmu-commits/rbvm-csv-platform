BEGIN;

-- V31 records the operational lifecycle that surrounds V30 source admission.
-- In particular, acquisition/build failures can happen before a V30 sync_run exists;
-- those attempts must still be durable and visible to operators.
CREATE TABLE rbvm.public_intelligence_sync_job (
    id uuid PRIMARY KEY,
    provider text NOT NULL CHECK (provider IN ('NVD', 'FIRST_EPSS', 'CISA_KEV', 'CVE_PROGRAM')),
    trigger_source text NOT NULL CHECK (trigger_source IN ('MANUAL', 'SCHEDULED', 'STARTUP', 'SYSTEM')),
    status text NOT NULL CHECK (status IN ('RUNNING', 'COMPLETE', 'FAILED')),
    stage text NOT NULL CHECK (stage IN ('ACQUIRING', 'BUILDING', 'ADMITTING', 'COMPLETE', 'FAILED')),
    started_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    completed_at timestamptz,
    source_uri text,
    source_version text,
    source_sha256 char(64),
    sync_run_id uuid,
    error_code text,
    error_detail text,
    FOREIGN KEY (provider, sync_run_id)
        REFERENCES rbvm.public_intelligence_sync_run(provider, id),
    CHECK (updated_at >= started_at),
    CHECK (completed_at IS NULL OR completed_at >= started_at),
    CHECK (
        (source_uri IS NULL AND source_version IS NULL AND source_sha256 IS NULL)
        OR
        (source_uri IS NOT NULL
            AND source_version IS NOT NULL
            AND source_sha256 IS NOT NULL
            AND length(trim(source_uri)) > 0
            AND source_uri ~* '^https://[^[:space:]]+$'
            AND length(trim(source_version)) > 0
            AND source_sha256 ~ '^[a-f0-9]{64}$')
    ),
    CHECK (
        (status = 'RUNNING'
            AND stage IN ('ACQUIRING', 'BUILDING', 'ADMITTING')
            AND completed_at IS NULL
            AND error_code IS NULL
            AND error_detail IS NULL)
        OR
        (status = 'COMPLETE'
            AND stage = 'COMPLETE'
            AND completed_at IS NOT NULL
            AND source_uri IS NOT NULL
            AND source_version IS NOT NULL
            AND source_sha256 IS NOT NULL
            AND sync_run_id IS NOT NULL
            AND error_code IS NULL
            AND error_detail IS NULL)
        OR
        (status = 'FAILED'
            AND stage = 'FAILED'
            AND completed_at IS NOT NULL
            AND error_code IS NOT NULL
            AND length(trim(error_code)) > 0
            AND error_detail IS NOT NULL
            AND length(trim(error_detail)) > 0)
    ),
    CHECK (stage = 'ACQUIRING' OR source_uri IS NOT NULL OR status = 'FAILED'),
    CHECK (sync_run_id IS NULL OR source_uri IS NOT NULL)
);

-- Prevent a manual/scheduled/startup collision from running two provider refreshes
-- concurrently. A terminal job releases the provider for retry or the next schedule.
CREATE UNIQUE INDEX public_intelligence_one_running_job_per_provider_idx
    ON rbvm.public_intelligence_sync_job(provider)
    WHERE status = 'RUNNING';

CREATE INDEX public_intelligence_sync_job_history_idx
    ON rbvm.public_intelligence_sync_job(provider, started_at DESC, id DESC);

CREATE FUNCTION rbvm.guard_public_intelligence_sync_job_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'public_intelligence_sync_job history cannot be deleted';
    END IF;

    IF OLD.status <> 'RUNNING' THEN
        RAISE EXCEPTION 'terminal public_intelligence_sync_job is immutable';
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.provider IS DISTINCT FROM OLD.provider
       OR NEW.trigger_source IS DISTINCT FROM OLD.trigger_source
       OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'public_intelligence_sync_job identity is immutable';
    END IF;

    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'public_intelligence_sync_job updated_at cannot move backwards';
    END IF;

    IF OLD.source_uri IS NOT NULL AND (
        NEW.source_uri IS DISTINCT FROM OLD.source_uri
        OR NEW.source_version IS DISTINCT FROM OLD.source_version
        OR NEW.source_sha256 IS DISTINCT FROM OLD.source_sha256
    ) THEN
        RAISE EXCEPTION 'public_intelligence_sync_job source identity is immutable once acquired';
    END IF;

    IF OLD.sync_run_id IS NOT NULL AND NEW.sync_run_id IS DISTINCT FROM OLD.sync_run_id THEN
        RAISE EXCEPTION 'public_intelligence_sync_job sync_run_id is immutable once linked';
    END IF;

    IF NEW.stage <> 'FAILED' THEN
        IF OLD.stage = 'ACQUIRING' AND NEW.stage <> 'BUILDING' THEN
            RAISE EXCEPTION 'public_intelligence_sync_job ACQUIRING may only advance to BUILDING';
        ELSIF OLD.stage = 'BUILDING' AND NEW.stage <> 'ADMITTING' THEN
            RAISE EXCEPTION 'public_intelligence_sync_job BUILDING may only advance to ADMITTING';
        ELSIF OLD.stage = 'ADMITTING' AND NEW.stage NOT IN ('ADMITTING', 'COMPLETE') THEN
            RAISE EXCEPTION 'public_intelligence_sync_job ADMITTING may only link a run or complete';
        END IF;
    END IF;

    IF OLD.stage = 'ADMITTING' AND NEW.stage = 'ADMITTING' AND NOT (
        OLD.sync_run_id IS NULL
        AND NEW.sync_run_id IS NOT NULL
        AND NEW.updated_at > OLD.updated_at
    ) THEN
        RAISE EXCEPTION 'public_intelligence_sync_job ADMITTING same-stage update must link one sync run';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER public_intelligence_sync_job_guard
BEFORE UPDATE OR DELETE ON rbvm.public_intelligence_sync_job
FOR EACH ROW EXECUTE FUNCTION rbvm.guard_public_intelligence_sync_job_mutation();

-- One read model for the future status API/UI. The job lifecycle is the latest
-- operational attempt (including pre-admission failures), while V30 remains the
-- authoritative last-successful source mirror.
CREATE VIEW rbvm.public_intelligence_provider_status_v1 AS
SELECT
    p.provider,
    j.id AS latest_job_id,
    j.trigger_source AS latest_job_trigger_source,
    j.status AS latest_job_status,
    j.stage AS latest_job_stage,
    j.started_at AS latest_job_started_at,
    j.updated_at AS latest_job_updated_at,
    j.completed_at AS latest_job_completed_at,
    j.source_uri AS latest_job_source_uri,
    j.source_version AS latest_job_source_version,
    j.source_sha256 AS latest_job_source_sha256,
    j.sync_run_id AS latest_job_sync_run_id,
    j.error_code AS latest_job_error_code,
    j.error_detail AS latest_job_error_detail,
    s.latest_success_id,
    s.latest_success_mode,
    s.latest_success_source_uri,
    s.latest_success_source_version,
    s.latest_success_source_sha256,
    s.latest_success_source_published_at,
    s.latest_success_observed_at,
    s.latest_success_completed_at,
    s.latest_success_record_count
FROM (VALUES
    ('NVD'::text),
    ('FIRST_EPSS'::text),
    ('CISA_KEV'::text),
    ('CVE_PROGRAM'::text)
) AS p(provider)
LEFT JOIN LATERAL (
    SELECT job.*
    FROM rbvm.public_intelligence_sync_job job
    WHERE job.provider = p.provider
    ORDER BY job.started_at DESC, job.id DESC
    LIMIT 1
) j ON true
LEFT JOIN rbvm.public_intelligence_source_status s
  ON s.provider = p.provider;

COMMENT ON TABLE rbvm.public_intelligence_sync_job IS
    'Global non-tenant operational synchronization lifecycle, including failures before a V30 source run can exist. It is not tenant evidence and does not calculate priority, risk, Treatment, or SLA.';
COMMENT ON VIEW rbvm.public_intelligence_provider_status_v1 IS
    'Unified four-provider operational status: latest end-to-end job plus the last successful V30 source mirror independently.';

COMMIT;
