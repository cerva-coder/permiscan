-- Safe scenarios. None of these objects should produce a finding.

-- RLS with ownership; anon has the default GRANT, but no policy reaches it.
CREATE TABLE public.notes (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id uuid NOT NULL DEFAULT auth.uid(),
    body text
);
ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_owner ON public.notes FOR ALL TO authenticated
    USING (owner_id = (SELECT auth.uid()))
    WITH CHECK (owner_id = (SELECT auth.uid()));

-- No RLS, but no privileges at all for the exposed roles.
CREATE TABLE public.internal_settings (key text PRIMARY KEY, value text);
REVOKE ALL ON public.internal_settings FROM anon, authenticated;

-- A view that honors the querying user's permissions.
CREATE VIEW public.my_notes WITH (security_invoker = true) AS
    SELECT id, body FROM public.notes;

-- Hardened SECURITY DEFINER, out of reach of the exposed roles.
CREATE FUNCTION public.rotate_settings() RETURNS void
    LANGUAGE sql SECURITY DEFINER SET search_path = ''
    AS $$ SELECT 1 $$;
REVOKE EXECUTE ON FUNCTION public.rotate_settings() FROM PUBLIC, anon, authenticated;

-- Table owner subject to RLS.
CREATE TABLE app.payments (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id text NOT NULL
);
ALTER TABLE app.payments OWNER TO app_user;
ALTER TABLE app.payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.payments FORCE ROW LEVEL SECURITY;
CREATE POLICY payments_tenant ON app.payments
    USING (tenant_id = current_setting('app.tenant_id', true));
