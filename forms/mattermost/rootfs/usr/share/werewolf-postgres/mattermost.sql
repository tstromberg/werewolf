-- Mattermost's role and schema, which pg-init applies before each start
-- (forms/postgresql/README.md). The role logs in by peer authentication
-- as the system user mattermost; its tables and its configuration go in
-- the schema of its name, the first on its search path, in the postgres
-- database, as a database of its own could not be made again without an
-- error.

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mattermost') THEN CREATE ROLE mattermost LOGIN; END IF; END $$;

CREATE SCHEMA IF NOT EXISTS mattermost AUTHORIZATION mattermost;
