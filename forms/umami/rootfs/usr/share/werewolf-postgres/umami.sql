-- Umami's role and schema, which pg-init applies before each start
-- (forms/postgresql/README.md). The role logs in over loopback TCP alone
-- (/etc/postgresql/pg_hba.conf); its tables go in the schema of its name,
-- in the postgres database, as a database of its own could not be made
-- again without an error.

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'umami') THEN CREATE ROLE umami LOGIN; END IF; END $$;

CREATE SCHEMA IF NOT EXISTS umami AUTHORIZATION umami;

-- Umami's first migration creates pgcrypto if it is not there, which its
-- role, owning no database, may not; so it is made here.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
