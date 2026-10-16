-- IRIS's role, which pg-init applies before each start
-- (forms/postgresql/README.md). IRIS logs in over loopback as the role
-- iris (pg_hba.conf) and keeps its tables in the postgres database,
-- which it owns. Its startup also creates the iris_tasks database. It
-- needs CREATEDB for that bootstrap, never SUPERUSER or CREATEROLE.

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iris') THEN CREATE ROLE iris LOGIN; END IF; END $$;

ALTER ROLE iris CREATEDB NOSUPERUSER NOCREATEROLE;

ALTER DATABASE postgres OWNER TO iris;
