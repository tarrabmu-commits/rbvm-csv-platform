BEGIN;

-- V30 introduces a global operational mirror of public vulnerability intelligence.
-- It is deliberately not tenant evidence and does not derive risk, priority, SLA,
-- customer context, or applicability. Only COMPLETE provider runs are eligible for
-- current lookup; failed/staging work can never displace the last good snapshot.
CREATE TABLE rbvm.public_intelligence_sync_run (
    id uuid PRIMARY KEY,
    provider text NOT NULL CHECK (provider IN ('NVD', 'FIRST_EPSS', 'CISA_KEV', 'CVE_PROGRAM')),
    sync_mode text NOT NULL CHECK (sync_mode IN ('BOOTSTRAP', 'INCREMENTAL')),
    status text NOT NULL CHECK (status IN ('STAGING', 'COMPLETE', 'FAILED')),
    source_uri text NOT NULL CHECK (
        length(trim(source_uri)) > 0
        AND source_uri ~* '^https://[^[:space:]]+$'
    ),
    source_version text NOT NULL CHECK (length(trim(source_version)) > 0),
    source_sha256 char(64) NOT NULL CHECK (source_sha256 ~ '^[a-f0-9]{64}$'),
    source_published_at timestamptz,
    observed_at timestamptz NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    record_count bigint CHECK (record_count IS NULL OR record_count >= 0),
    error_code text,
    error_detail text,
    UNIQUE (provider, id),
    CHECK (source_published_at IS NULL OR source_published_at <= observed_at),
    CHECK (started_at <= observed_at),
    CHECK (
        (status = 'STAGING'
            AND completed_at IS NULL
            AND record_count IS NULL
            AND error_code IS NULL
            AND error_detail IS NULL)
        OR
        (status = 'COMPLETE'
            AND completed_at IS NOT NULL
            AND completed_at >= started_at
            AND record_count IS NOT NULL
            AND error_code IS NULL
            AND error_detail IS NULL)
        OR
        (status = 'FAILED'
            AND completed_at IS NOT NULL
            AND completed_at >= started_at
            AND error_code IS NOT NULL
            AND length(trim(error_code)) > 0
            AND error_detail IS NOT NULL
            AND length(trim(error_detail)) > 0)
    )
);

-- One validated source payload may have at most one active/complete ingestion.
-- FAILED runs are intentionally excluded so an identical source can be retried.
CREATE UNIQUE INDEX public_intelligence_nonfailed_source_idx
    ON rbvm.public_intelligence_sync_run(provider, source_sha256)
    WHERE status IN ('STAGING', 'COMPLETE');

CREATE INDEX public_intelligence_sync_status_idx
    ON rbvm.public_intelligence_sync_run(provider, started_at DESC, id DESC);

CREATE TABLE rbvm.public_intelligence_record (
    sync_run_id uuid NOT NULL,
    provider text NOT NULL CHECK (provider IN ('NVD', 'FIRST_EPSS', 'CISA_KEV', 'CVE_PROGRAM')),
    cve_id text NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    record_state text NOT NULL CHECK (record_state IN ('ACTIVE', 'TOMBSTONE')),
    source_modified_at timestamptz,
    source_published_at timestamptz,
    payload_json jsonb,
    record_sha256 char(64) NOT NULL CHECK (record_sha256 ~ '^[a-f0-9]{64}$'),
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (sync_run_id, cve_id),
    FOREIGN KEY (provider, sync_run_id)
        REFERENCES rbvm.public_intelligence_sync_run(provider, id),
    CHECK (
        (record_state = 'ACTIVE' AND payload_json IS NOT NULL)
        OR (record_state = 'TOMBSTONE' AND payload_json IS NULL)
    ),
    CHECK (source_published_at IS NULL OR source_modified_at IS NULL
        OR source_published_at <= source_modified_at)
);

CREATE INDEX public_intelligence_record_lookup_idx
    ON rbvm.public_intelligence_record(
        provider,
        cve_id,
        source_modified_at DESC,
        source_published_at DESC,
        observed_at DESC
    );

CREATE INDEX public_intelligence_record_run_idx
    ON rbvm.public_intelligence_record(sync_run_id, cve_id);

CREATE FUNCTION rbvm.guard_public_intelligence_sync_run_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'public_intelligence_sync_run history cannot be deleted';
    END IF;

    IF OLD.status <> 'STAGING' THEN
        RAISE EXCEPTION 'terminal public_intelligence_sync_run is immutable';
    END IF;

    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.provider IS DISTINCT FROM OLD.provider
       OR NEW.sync_mode IS DISTINCT FROM OLD.sync_mode
       OR NEW.source_uri IS DISTINCT FROM OLD.source_uri
       OR NEW.source_version IS DISTINCT FROM OLD.source_version
       OR NEW.source_sha256 IS DISTINCT FROM OLD.source_sha256
       OR NEW.source_published_at IS DISTINCT FROM OLD.source_published_at
       OR NEW.observed_at IS DISTINCT FROM OLD.observed_at
       OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'public_intelligence_sync_run source identity is immutable';
    END IF;

    IF NEW.status NOT IN ('COMPLETE', 'FAILED') THEN
        RAISE EXCEPTION 'public_intelligence_sync_run only permits STAGING to terminal transition';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER public_intelligence_sync_run_guard
BEFORE UPDATE OR DELETE ON rbvm.public_intelligence_sync_run
FOR EACH ROW EXECUTE FUNCTION rbvm.guard_public_intelligence_sync_run_mutation();

CREATE FUNCTION rbvm.require_public_intelligence_staging_run()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    run_status text;
BEGIN
    SELECT status INTO run_status
    FROM rbvm.public_intelligence_sync_run
    WHERE id = NEW.sync_run_id AND provider = NEW.provider;

    IF run_status IS DISTINCT FROM 'STAGING' THEN
        RAISE EXCEPTION 'public intelligence records may only be appended to a STAGING run';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER public_intelligence_record_staging_guard
BEFORE INSERT ON rbvm.public_intelligence_record
FOR EACH ROW EXECUTE FUNCTION rbvm.require_public_intelligence_staging_run();

CREATE FUNCTION rbvm.forbid_public_intelligence_record_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'public_intelligence_record is append-only';
END;
$$;

CREATE TRIGGER public_intelligence_record_append_only
BEFORE UPDATE OR DELETE ON rbvm.public_intelligence_record
FOR EACH ROW EXECUTE FUNCTION rbvm.forbid_public_intelligence_record_mutation();

-- Resolve the newest provider statement first, including TOMBSTONE. Filtering
-- tombstones before this DISTINCT would incorrectly resurrect an older record.
CREATE VIEW rbvm.latest_public_intelligence_record AS
SELECT DISTINCT ON (r.provider, e.cve_id)
    r.provider,
    e.cve_id,
    e.record_state,
    e.payload_json,
    e.record_sha256,
    e.source_modified_at,
    e.source_published_at,
    e.observed_at AS record_observed_at,
    r.id AS sync_run_id,
    r.sync_mode,
    r.source_uri,
    r.source_version,
    r.source_sha256,
    r.source_published_at AS run_source_published_at,
    r.observed_at AS run_observed_at,
    r.completed_at AS run_completed_at,
    COALESCE(
        e.source_modified_at,
        e.source_published_at,
        r.source_published_at,
        r.observed_at
    ) AS effective_source_time
FROM rbvm.public_intelligence_record e
JOIN rbvm.public_intelligence_sync_run r
  ON r.id = e.sync_run_id
 AND r.provider = e.provider
WHERE r.status = 'COMPLETE'
ORDER BY
    r.provider,
    e.cve_id,
    COALESCE(
        e.source_modified_at,
        e.source_published_at,
        r.source_published_at,
        r.observed_at
    ) DESC,
    r.completed_at DESC,
    e.observed_at DESC,
    r.id DESC;

CREATE VIEW rbvm.current_public_intelligence_record AS
SELECT *
FROM rbvm.latest_public_intelligence_record
WHERE record_state = 'ACTIVE';

-- Always expose all supported providers so the future Intelligence Sources UI
-- can distinguish never-synced from failed/stale/successful source state.
CREATE VIEW rbvm.public_intelligence_source_status AS
SELECT
    p.provider,
    a.id AS latest_attempt_id,
    a.status AS latest_attempt_status,
    a.sync_mode AS latest_attempt_mode,
    a.started_at AS latest_attempt_started_at,
    a.completed_at AS latest_attempt_completed_at,
    a.error_code AS latest_attempt_error_code,
    a.error_detail AS latest_attempt_error_detail,
    s.id AS latest_success_id,
    s.sync_mode AS latest_success_mode,
    s.source_uri AS latest_success_source_uri,
    s.source_version AS latest_success_source_version,
    s.source_sha256 AS latest_success_source_sha256,
    s.source_published_at AS latest_success_source_published_at,
    s.observed_at AS latest_success_observed_at,
    s.completed_at AS latest_success_completed_at,
    s.record_count AS latest_success_record_count
FROM (VALUES
    ('NVD'::text),
    ('FIRST_EPSS'::text),
    ('CISA_KEV'::text),
    ('CVE_PROGRAM'::text)
) AS p(provider)
LEFT JOIN LATERAL (
    SELECT r.*
    FROM rbvm.public_intelligence_sync_run r
    WHERE r.provider = p.provider
    ORDER BY r.started_at DESC, r.id DESC
    LIMIT 1
) a ON true
LEFT JOIN LATERAL (
    SELECT r.*
    FROM rbvm.public_intelligence_sync_run r
    WHERE r.provider = p.provider AND r.status = 'COMPLETE'
    ORDER BY r.completed_at DESC, r.id DESC
    LIMIT 1
) s ON true;

COMMENT ON TABLE rbvm.public_intelligence_sync_run IS
    'Global non-tenant operational source mirror provenance for NVD, FIRST EPSS, CISA KEV, and CVE Program synchronization. It is not customer evidence or a risk/priority result.';
COMMENT ON TABLE rbvm.public_intelligence_record IS
    'Append-only CVE records from one exact public-source sync run. ACTIVE carries source JSON; TOMBSTONE explicitly suppresses older provider state after a complete run.';
COMMENT ON VIEW rbvm.current_public_intelligence_record IS
    'Current global public-source mirror after complete-run and tombstone resolution. Consumers must still apply provider-specific completeness/evidence admission semantics.';
COMMENT ON VIEW rbvm.public_intelligence_source_status IS
    'Latest attempt and latest successful complete synchronization independently per supported public provider.';

COMMIT;
