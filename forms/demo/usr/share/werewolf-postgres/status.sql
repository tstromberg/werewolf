-- The demo's page and scan keep what they find here (status/status.zig).
-- The status role owns it; grype may add scans and nothing more. pg-init
-- applies this before every start of the server, so each statement is one
-- that changes nothing the second time. In single-user mode, a statement
-- ends at a semicolon before an empty line.

DO $$ BEGIN CREATE ROLE status LOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN CREATE ROLE grype LOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;

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
