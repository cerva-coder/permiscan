-- Cenários vulneráveis. Cada objeto documenta o finding esperado.

-- pg-rls-disabled (critical): dados multi-tenant sem RLS, com GRANT padrão.
CREATE TABLE public.invoices (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id uuid NOT NULL,
    amount_cents bigint NOT NULL
);

-- pg-rls-disabled com policies ignoradas.
CREATE TABLE public.audit_entries (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor uuid NOT NULL
);
CREATE POLICY audit_owner ON public.audit_entries USING (actor = auth.uid());

-- pg-policy-unrestricted: SELECT público (medium) e UPDATE irrestrito (high).
CREATE TABLE public.profiles (
    id uuid PRIMARY KEY,
    display_name text
);
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY profiles_read ON public.profiles FOR SELECT USING (true);
CREATE POLICY profiles_update ON public.profiles FOR UPDATE TO authenticated USING (true);

-- pg-policy-no-ownership: escrita condicionada só à existência de org_id.
CREATE TABLE public.documents (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id uuid,
    body text
);
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY documents_write ON public.documents FOR ALL TO authenticated
    USING (org_id IS NOT NULL);

-- pg-view-definer: view sem security_invoker sobre dados sensíveis.
CREATE VIEW public.invoice_totals AS
    SELECT org_id, sum(amount_cents) AS total FROM public.invoices GROUP BY org_id;

-- pg-matview-exposed
CREATE MATERIALIZED VIEW public.profile_index AS SELECT id, display_name FROM public.profiles;
GRANT SELECT ON public.profile_index TO anon, authenticated;

-- pg-func-secdef-exposed + pg-func-search-path
CREATE FUNCTION public.all_invoices() RETURNS SETOF public.invoices
    LANGUAGE sql SECURITY DEFINER
    AS $$ SELECT * FROM public.invoices $$;

-- pg-rls-owner-bypass: RLS habilitado, mas o papel da aplicação é o dono.
CREATE TABLE app.orders (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id text NOT NULL
);
ALTER TABLE app.orders OWNER TO app_user;
ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_tenant ON app.orders
    USING (tenant_id = current_setting('app.tenant_id', true));
