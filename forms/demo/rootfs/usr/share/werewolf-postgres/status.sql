-- The demo's page and scan keep what they find here (forms/demo/cmd/status-page/status-page.zig).
-- The status role owns it; grype may add scans and nothing more. pg-init
-- applies this before every start of the server, so each statement is one
-- that changes nothing the second time, and raises no error doing so:
-- pg-init stops at the first error, which then no EXCEPTION clause can
-- catch, so a role is made only where pg_roles has none. In single-user
-- mode, a statement ends at a semicolon before an empty line.

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'status') THEN CREATE ROLE status LOGIN; END IF; END $$;

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'grype') THEN CREATE ROLE grype LOGIN; END IF; END $$;

CREATE SCHEMA IF NOT EXISTS status AUTHORIZATION status;

CREATE TABLE IF NOT EXISTS status.posture (
    boot   text PRIMARY KEY,
    at     timestamptz NOT NULL DEFAULT now(),
    report jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS status.scans (
    at      timestamptz PRIMARY KEY DEFAULT clock_timestamp(),
    summary jsonb NOT NULL
);

ALTER TABLE status.posture OWNER TO status;

ALTER TABLE status.scans OWNER TO status;

GRANT USAGE ON SCHEMA status TO grype;

GRANT INSERT ON status.scans TO grype;
