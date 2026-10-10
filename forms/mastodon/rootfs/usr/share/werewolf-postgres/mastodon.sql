-- Mastodon's roles, which pg-init applies before each start
-- (forms/postgresql/README.md). Each logs in by peer authentication as
-- the system user of its name. mastodon owns the database, which the web's
-- db:prepare makes on the first start; the jobs' and cron's roles are
-- members of it, with its rights; mastodon-stream, the streaming server's,
-- may only read it (forms/mastodon/rootfs/usr/share/werewolf-mastodon/owner.rb).
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mastodon') THEN
    CREATE ROLE mastodon LOGIN CREATEDB;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mastodon-jobs') THEN
    CREATE ROLE "mastodon-jobs" LOGIN IN ROLE mastodon;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mastodon-cron') THEN
    CREATE ROLE "mastodon-cron" LOGIN IN ROLE mastodon;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mastodon-stream') THEN
    CREATE ROLE "mastodon-stream" LOGIN;
  END IF;
END
$$;
