-- Emula o modelo de papéis do Supabase em um PostgreSQL comum.
-- Dados 100% sintéticos; uso exclusivo em laboratório local.

CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE service_role NOLOGIN BYPASSRLS;

-- Papel usado pelo PermiScan: login sem privilégios além do padrão.
-- Prova que a análise funciona com privilégio mínimo.
CREATE ROLE permiscan_auditor LOGIN PASSWORD 'auditor-lab-only';

CREATE SCHEMA auth;
CREATE FUNCTION auth.uid() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;

GRANT USAGE ON SCHEMA public, auth TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.uid() TO anon, authenticated;

-- Padrão do Supabase: tudo o que é criado em public já nasce concedido aos papéis da API.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO anon, authenticated, service_role;

-- Aplicação PostgreSQL "pura": papel da aplicação dono das próprias tabelas.
CREATE ROLE app_user NOLOGIN;
CREATE SCHEMA app AUTHORIZATION app_user;
