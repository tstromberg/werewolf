DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'unifi-core') THEN CREATE ROLE "unifi-core" LOGIN; END IF; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'unifi_network_admin') THEN CREATE ROLE unifi_network_admin LOGIN CREATEDB; END IF; END $$;
ALTER DATABASE postgres OWNER TO "unifi-core";
GRANT ALL ON SCHEMA public TO "unifi-core";
