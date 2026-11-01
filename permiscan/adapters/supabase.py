from typing import Any

from permiscan.adapters.base import AdapterError
from permiscan.adapters.postgres import PostgresAdapter
from permiscan.scope import Target


class SupabaseAdapter(PostgresAdapter):
    """Supabase é PostgreSQL exposto pelo PostgREST: auditamos os papéis que o
    PostgREST assume para requisições anônimas e autenticadas."""

    provider = "supabase"
    DEFAULT_ROLES = ["anon", "authenticated"]
    DEFAULT_SCHEMAS = ["public"]  # schema exposto pela Data API por padrão

    def __init__(self, target: Target, roles: list[str] | None = None, schemas: list[str] | None = None):
        super().__init__(target, roles or self.DEFAULT_ROLES, schemas or self.DEFAULT_SCHEMAS)

    def check(self) -> dict[str, Any]:
        info = super().check()
        if info["missing_roles"]:
            raise AdapterError(
                f"{self.target.label} não parece um projeto Supabase: papéis ausentes "
                f"{', '.join(info['missing_roles'])}"
            )
        return info
