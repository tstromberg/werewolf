-- Nextcloud's roles, which pg-init applies before each start
-- (forms/postgresql/README.md). Each logs in by peer authentication as
-- the system user of its name. nextcloud may make its own database,
-- which Nextcloud's installer does on the first start, and owns it; the
-- background jobs' role is a member of it, and acts as it, so what a job
-- makes is Nextcloud's too.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nextcloud') THEN
    CREATE ROLE nextcloud LOGIN CREATEDB;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nextcloud-cron') THEN
    CREATE ROLE "nextcloud-cron" LOGIN IN ROLE nextcloud;
  END IF;
END
$$;

ALTER ROLE "nextcloud-cron" SET role = 'nextcloud';
