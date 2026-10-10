-- Moodle's roles and schema, which pg-init applies before each start
-- (forms/postgresql/README.md). Each role logs in by peer authentication
-- as the system user of its name. moodle owns the schema moodle in the
-- postgres database, where Moodle's tables go ($CFG->dboptions dbschema),
-- as a database of its own could not be made again without an error;
-- cron's role is a member of moodle, and acts as it, so what a task makes
-- is Moodle's too.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'moodle') THEN
    CREATE ROLE moodle LOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'moodle-cron') THEN
    CREATE ROLE "moodle-cron" LOGIN IN ROLE moodle;
  END IF;
END
$$;

ALTER ROLE "moodle-cron" SET role = 'moodle';

CREATE SCHEMA IF NOT EXISTS moodle AUTHORIZATION moodle;
