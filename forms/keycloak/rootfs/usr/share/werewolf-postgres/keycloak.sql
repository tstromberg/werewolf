-- Keycloak's role and schema, which pg-init applies before each start
-- (forms/postgresql/README.md). The role logs in by peer authentication
-- as the system user keycloak, over the socket; its tables go in the
-- schema of its name (KC_DB_SCHEMA) in the postgres database, as a
-- database of its own could not be made again without an error.

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'keycloak') THEN CREATE ROLE keycloak LOGIN; END IF; END $$;

CREATE SCHEMA IF NOT EXISTS keycloak AUTHORIZATION keycloak;
