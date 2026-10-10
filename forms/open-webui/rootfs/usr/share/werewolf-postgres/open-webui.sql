-- Open WebUI's role and schema, which pg-init applies before each start
-- (forms/postgresql/README.md). The role logs in by peer authentication
-- as the system user open-webui; its tables, and pgvector's type for the
-- documents it embeds, go in the schema of its name, the first on its
-- search path, in the postgres database. An extension is a superuser's to
-- make, so it is made here, where Open WebUI's own CREATE EXTENSION IF
-- NOT EXISTS finds it.

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'open-webui') THEN CREATE ROLE "open-webui" LOGIN; END IF; END $$;

CREATE SCHEMA IF NOT EXISTS "open-webui" AUTHORIZATION "open-webui";

CREATE EXTENSION IF NOT EXISTS vector SCHEMA "open-webui";
