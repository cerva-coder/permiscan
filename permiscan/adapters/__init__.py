from permiscan.adapters.postgres import PostgresAdapter
from permiscan.adapters.supabase import SupabaseAdapter

PROVIDERS = {a.provider: a for a in (PostgresAdapter, SupabaseAdapter)}
