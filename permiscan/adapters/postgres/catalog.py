"""Read-only collection of the PostgreSQL catalog into an immutable snapshot.

Rules operate on the snapshot, never on the connection: this keeps them pure,
testable without a database, and reusable by any PostgreSQL-based provider.
"""

from dataclasses import dataclass, field

import psycopg

KIND = {"r": "table", "p": "partitioned_table", "v": "view", "m": "materialized_view"}
TABLE_KINDS = {"table", "partitioned_table"}


@dataclass(frozen=True)
class Role:
    name: str
    superuser: bool
    bypass_rls: bool


@dataclass(frozen=True)
class Relation:
    schema: str
    name: str
    kind: str
    owner: str
    rls_enabled: bool
    rls_forced: bool
    security_invoker: bool
    # effective privileges (inheritance and PUBLIC included) of each audited role
    privileges: dict[str, frozenset[str]] = field(default_factory=dict)
    # audited roles that own the relation, directly or via inheritance
    owned_by: frozenset[str] = frozenset()

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass(frozen=True)
class Policy:
    schema: str
    table: str
    name: str
    permissive: bool
    roles: tuple[str, ...]
    cmd: str  # ALL | SELECT | INSERT | UPDATE | DELETE
    qual: str | None
    with_check: str | None


@dataclass(frozen=True)
class Function:
    schema: str
    name: str
    args: str
    owner: str
    search_path_set: bool
    executable_by: frozenset[str]

    @property
    def signature(self) -> str:
        return f"{self.schema}.{self.name}({self.args})"


@dataclass(frozen=True)
class Snapshot:
    schemas: tuple[str, ...]
    roles: tuple[Role, ...]
    relations: tuple[Relation, ...]
    policies: tuple[Policy, ...]
    security_definer_functions: tuple[Function, ...]


_NOT_EXTENSION_MEMBER = """
    NOT EXISTS (SELECT 1 FROM pg_depend d
                WHERE d.classid = '{cls}'::regclass AND d.objid = {oid} AND d.deptype = 'e')
"""

_RELATIONS = f"""
SELECT n.nspname, c.relname, c.relkind, pg_get_userbyid(c.relowner),
       c.relrowsecurity, c.relforcerowsecurity, coalesce(c.reloptions, '{{}}'),
       r.rolname,
       CASE WHEN has_schema_privilege(r.oid, n.oid, 'USAGE') THEN array_remove(ARRAY[
           CASE WHEN has_any_column_privilege(r.oid, c.oid, 'SELECT') THEN 'SELECT' END,
           CASE WHEN has_any_column_privilege(r.oid, c.oid, 'INSERT') THEN 'INSERT' END,
           CASE WHEN has_any_column_privilege(r.oid, c.oid, 'UPDATE') THEN 'UPDATE' END,
           CASE WHEN has_table_privilege(r.oid, c.oid, 'DELETE') THEN 'DELETE' END
       ], NULL) ELSE '{{}}'::text[] END,
       pg_has_role(r.oid, c.relowner, 'USAGE')
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_roles r ON r.rolname = ANY(%s)
WHERE c.relkind IN ('r', 'p', 'v', 'm')
  AND n.nspname = ANY(%s)
  AND {_NOT_EXTENSION_MEMBER.format(cls="pg_class", oid="c.oid")}
ORDER BY 1, 2, r.rolname
"""

_POLICIES = """
SELECT schemaname, tablename, policyname, permissive = 'PERMISSIVE', roles::text[], cmd, qual, with_check
FROM pg_policies
WHERE schemaname = ANY(%s)
ORDER BY 1, 2, 3
"""

_SECURITY_DEFINER_FUNCTIONS = f"""
SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), pg_get_userbyid(p.proowner),
       EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, '{{}}')) cfg WHERE starts_with(cfg, 'search_path=')),
       ARRAY(SELECT r.rolname FROM pg_roles r
             WHERE r.rolname = ANY(%s)
               AND has_schema_privilege(r.oid, n.oid, 'USAGE')
               AND has_function_privilege(r.oid, p.oid, 'EXECUTE'))
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef
  AND n.nspname = ANY(%s)
  AND {_NOT_EXTENSION_MEMBER.format(cls="pg_proc", oid="p.oid")}
ORDER BY 1, 2, 3
"""

_ROLES = "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = ANY(%s) ORDER BY 1"

USER_SCHEMAS = """
SELECT nspname FROM pg_namespace
WHERE NOT starts_with(nspname, 'pg_') AND nspname <> 'information_schema'
ORDER BY 1
"""


def _security_invoker(options: list[str]) -> bool:
    for opt in options:
        key, _, value = opt.partition("=")
        if key == "security_invoker":
            return value.lower() in {"true", "on", "1", "yes"}
    return False


def collect(conn: psycopg.Connection, schemas: list[str], roles: list[str]) -> Snapshot:
    rels: dict[tuple[str, str], dict] = {}
    for schema, name, kind, owner, rls, forced, options, role, privs, owns in conn.execute(
        _RELATIONS, (roles, schemas)
    ):
        rel = rels.setdefault((schema, name), {
            "schema": schema, "name": name, "kind": KIND[kind], "owner": owner,
            "rls_enabled": rls, "rls_forced": forced,
            "security_invoker": _security_invoker(options),
            "privileges": {}, "owned_by": set(),
        })
        if role is None:
            continue
        rel["privileges"][role] = frozenset(privs)
        if owns:
            rel["owned_by"].add(role)

    return Snapshot(
        schemas=tuple(schemas),
        roles=tuple(Role(*row) for row in conn.execute(_ROLES, (roles,))),
        relations=tuple(Relation(**{**r, "owned_by": frozenset(r["owned_by"])}) for r in rels.values()),
        policies=tuple(
            Policy(s, t, n, perm, tuple(rs), cmd, q, wc)
            for s, t, n, perm, rs, cmd, q, wc in conn.execute(_POLICIES, (schemas,))
        ),
        security_definer_functions=tuple(
            Function(s, n, a, o, sp, frozenset(ex))
            for s, n, a, o, sp, ex in conn.execute(_SECURITY_DEFINER_FUNCTIONS, (roles, schemas))
        ),
    )
