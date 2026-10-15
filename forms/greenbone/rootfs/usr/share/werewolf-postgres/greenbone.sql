-- gvmd's role, which pg-init applies before each start
-- (forms/postgresql/README.md). gvmd logs in over loopback as the role
-- gvmd (pg_hba.conf) and keeps its tables in the postgres database,
-- which it owns.

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gvmd') THEN CREATE ROLE gvmd LOGIN CREATEDB; END IF; END $$;

-- gvmd issues SET ROLE dba / RESET ROLE internally. Use an ordinary owner
-- role as its connection default, so both paths own the same objects.
-- Privileged extension installation stays here in offline postgres setup.
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dba') THEN CREATE ROLE dba NOLOGIN NOSUPERUSER NOCREATEROLE CREATEDB; END IF; END $$;

GRANT dba TO gvmd;

ALTER ROLE gvmd SET role = 'dba';

ALTER DATABASE postgres OWNER TO dba;

-- Install the privileged extensions during offline cluster setup, while
-- pg-init is postgres. The network login remains an ordinary database owner.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE EXTENSION IF NOT EXISTS "pg-gvm";
