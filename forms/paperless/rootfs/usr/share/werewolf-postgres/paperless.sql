-- pg-init applies this before PostgreSQL starts. Each component logs in
-- as its UNIX user by peer authentication. Only the web user owns schema.

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'paperless') THEN CREATE ROLE paperless LOGIN; END IF; END $$;

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'paperless-consumer') THEN CREATE ROLE "paperless-consumer" LOGIN; END IF; END $$;

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'paperless-worker') THEN CREATE ROLE "paperless-worker" LOGIN; END IF; END $$;

DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'paperless-beat') THEN CREATE ROLE "paperless-beat" LOGIN; END IF; END $$;

CREATE SCHEMA IF NOT EXISTS paperless AUTHORIZATION paperless;

ALTER ROLE paperless IN DATABASE postgres SET search_path = paperless;

ALTER ROLE "paperless-consumer" IN DATABASE postgres SET search_path = paperless;

ALTER ROLE "paperless-worker" IN DATABASE postgres SET search_path = paperless;

ALTER ROLE "paperless-beat" IN DATABASE postgres SET search_path = paperless;

GRANT USAGE ON SCHEMA paperless TO "paperless-consumer", "paperless-worker", "paperless-beat";

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA paperless TO "paperless-consumer", "paperless-worker", "paperless-beat";

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA paperless TO "paperless-consumer", "paperless-worker", "paperless-beat";

ALTER DEFAULT PRIVILEGES FOR ROLE paperless IN SCHEMA paperless GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "paperless-consumer", "paperless-worker", "paperless-beat";

ALTER DEFAULT PRIVILEGES FOR ROLE paperless IN SCHEMA paperless GRANT USAGE, SELECT ON SEQUENCES TO "paperless-consumer", "paperless-worker", "paperless-beat";
