from collections.abc import Callable
from typing import Any

import psycopg

from permiscan.adapters.base import Adapter, AdapterError, Capability
from permiscan.adapters.postgres.catalog import USER_SCHEMAS, collect
from permiscan.adapters.postgres.rules import analyze
from permiscan.findings import Finding
from permiscan.scope import Target


class PostgresAdapter(Adapter):
    provider = "postgresql"
    capabilities = frozenset(Capability)

    def __init__(self, target: Target, roles: list[str] | None = None, schemas: list[str] | None = None):
        if not roles:
            raise AdapterError("provide at least one role to audit (--role)")
        self.target = target
        self.roles = roles
        self.schemas = schemas  # None = all user schemas

    def _session[T](self, work: Callable[[psycopg.Connection], T]) -> T:
        try:
            with psycopg.connect(**self.target.connect_kwargs(), connect_timeout=10, application_name="permiscan") as conn:
                # The whole session runs in a single READ ONLY transaction, pooler-compatible.
                conn.read_only = True
                conn.execute("SET LOCAL statement_timeout = '30s'")
                result = work(conn)
                conn.rollback()
                return result
        except psycopg.Error as e:
            # from None: the original exception chain never reaches the logs
            raise AdapterError(self.target.redact(f"{self.target.label}: {e}".strip())) from None

    def _schemas(self, conn: psycopg.Connection) -> list[str]:
        return self.schemas or [s for (s,) in conn.execute(USER_SCHEMAS)]

    def check(self) -> dict[str, Any]:
        def work(conn: psycopg.Connection) -> dict[str, Any]:
            version, user, superuser, read_only = conn.execute(
                "SELECT current_setting('server_version'), current_user, rolsuper,"
                " current_setting('transaction_read_only') FROM pg_roles WHERE rolname = current_user"
            ).fetchone()
            schemas = self._schemas(conn)
            found_schemas = {s for (s,) in conn.execute("SELECT nspname FROM pg_namespace WHERE nspname = ANY(%s)", (schemas,))}
            found_roles = {r for (r,) in conn.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (self.roles,))}
            return {
                "provider": self.provider,
                "target": self.target.label,
                "server_version": version,
                "connected_as": user,
                "connected_as_superuser": superuser,
                "read_only": read_only == "on",
                "schemas": schemas,
                "missing_schemas": [s for s in schemas if s not in found_schemas],
                "audited_roles": self.roles,
                "missing_roles": [r for r in self.roles if r not in found_roles],
                "capabilities": sorted(self.capabilities),
            }

        return self._session(work)

    def scan(self) -> list[Finding]:
        snapshot = self._session(lambda conn: collect(conn, self._schemas(conn), self.roles))
        return analyze(snapshot, self.provider)
