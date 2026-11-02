-- Emulates Supabase's role model on top of plain PostgreSQL.
-- Fully synthetic data; local-lab use only.

CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE service_role NOLOGIN BYPASSRLS;

-- Role used by PermiScan: login with no privileges beyond the default.
-- Proves the analysis works with minimal privilege.
CREATE ROLE permiscan_auditor LOGIN PASSWORD 'auditor-lab-only';

CREATE SCHEMA auth;
CREATE FUNCTION auth.uid() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;

GRANT USAGE ON SCHEMA public, auth TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.uid() TO anon, authenticated;

-- Supabase default: anything created in public is already granted to the API roles.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO anon, authenticated, service_role;

-- "Plain" PostgreSQL application: an app role that owns its own tables.
CREATE ROLE app_user NOLOGIN;
CREATE SCHEMA app AUTHORIZATION app_user;
