-- Immich's role and extensions, which pg-init applies before each start
-- (forms/postgresql/README.md). Immich logs in over loopback as the role
-- immich (pg_hba.conf) and keeps its tables in the postgres database,
-- which it owns, with its public schema: its migrations set the
-- database's search_path, which only an owner may, and a database of its
-- own could not be made again without an error. The extensions are made
-- here, by the superuser, so Immich's own CREATE EXTENSION IF NOT EXISTS
-- finds them and needs no more rights.

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'immich') THEN CREATE ROLE immich LOGIN; END IF; END $$;

ALTER DATABASE postgres OWNER TO immich;

CREATE EXTENSION IF NOT EXISTS vector;

CREATE EXTENSION IF NOT EXISTS cube;

CREATE EXTENSION IF NOT EXISTS earthdistance;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE EXTENSION IF NOT EXISTS unaccent;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
