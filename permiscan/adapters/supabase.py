from typing import Any

from permiscan.adapters.base import AdapterError
from permiscan.adapters.postgres import PostgresAdapter
from permiscan.scope import Target


class SupabaseAdapter(PostgresAdapter):
    """Supabase is PostgreSQL exposed through PostgREST: we audit the roles that
    PostgREST assumes for anonymous and authenticated requests."""

    provider = "supabase"
    DEFAULT_ROLES = ["anon", "authenticated"]
    DEFAULT_SCHEMAS = ["public"]  # schema exposed by the Data API by default

    def __init__(self, target: Target, roles: list[str] | None = None, schemas: list[str] | None = None):
        super().__init__(target, roles or self.DEFAULT_ROLES, schemas or self.DEFAULT_SCHEMAS)

    def check(self) -> dict[str, Any]:
        info = super().check()
        if info["missing_roles"]:
            raise AdapterError(
                f"{self.target.label} doesn't look like a Supabase project: missing roles "
                f"{', '.join(info['missing_roles'])}"
            )
        return info
