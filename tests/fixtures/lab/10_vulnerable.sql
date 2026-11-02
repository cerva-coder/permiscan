-- Vulnerable scenarios. Each object documents the expected finding.

-- pg-rls-disabled (critical): multi-tenant data with no RLS, with the default GRANT.
CREATE TABLE public.invoices (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id uuid NOT NULL,
    amount_cents bigint NOT NULL
);

-- pg-rls-disabled with ignored policies.
CREATE TABLE public.audit_entries (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor uuid NOT NULL
);
CREATE POLICY audit_owner ON public.audit_entries USING (actor = auth.uid());

-- pg-policy-unrestricted: public SELECT (medium) and unrestricted UPDATE (high).
CREATE TABLE public.profiles (
    id uuid PRIMARY KEY,
    display_name text
);
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY profiles_read ON public.profiles FOR SELECT USING (true);
CREATE POLICY profiles_update ON public.profiles FOR UPDATE TO authenticated USING (true);

-- pg-policy-no-ownership: write gated only on org_id existing, not on who owns it.
CREATE TABLE public.documents (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id uuid,
    body text
);
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY documents_write ON public.documents FOR ALL TO authenticated
    USING (org_id IS NOT NULL);

-- pg-view-definer: view without security_invoker over sensitive data.
CREATE VIEW public.invoice_totals AS
    SELECT org_id, sum(amount_cents) AS total FROM public.invoices GROUP BY org_id;

-- pg-matview-exposed
CREATE MATERIALIZED VIEW public.profile_index AS SELECT id, display_name FROM public.profiles;
GRANT SELECT ON public.profile_index TO anon, authenticated;

-- pg-func-secdef-exposed + pg-func-search-path
CREATE FUNCTION public.all_invoices() RETURNS SETOF public.invoices
    LANGUAGE sql SECURITY DEFINER
    AS $$ SELECT * FROM public.invoices $$;

-- pg-rls-owner-bypass: RLS enabled, but the application role is the owner.
CREATE TABLE app.orders (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id text NOT NULL
);
ALTER TABLE app.orders OWNER TO app_user;
ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_tenant ON app.orders
    USING (tenant_id = current_setting('app.tenant_id', true));
