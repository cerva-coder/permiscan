"""Static rules over the PostgreSQL catalog snapshot.

Every rule cross-references the configuration with the effective privileges of the
audited roles: a permissive policy or a disabled RLS only becomes a finding when
some exposed role can actually perform the operation.
"""

import re
from collections.abc import Iterator

from permiscan.adapters.postgres.catalog import TABLE_KINDS, Policy, Relation, Snapshot
from permiscan.findings import Category, Confidence, Finding, Remediation, Severity

WRITE = frozenset({"INSERT", "UPDATE", "DELETE"})
CMD_PRIVILEGES = {
    "SELECT": frozenset({"SELECT"}),
    "INSERT": frozenset({"INSERT"}),
    "UPDATE": frozenset({"UPDATE"}),
    "DELETE": frozenset({"DELETE"}),
    "ALL": frozenset({"SELECT"}) | WRITE,
}

# References that tie the expression to the identity of the requester.
# ponytail: textual heuristic; helper functions (e.g. is_member()) produce false
# positives, so findings from this stay at "possible" confidence.
_IDENTITY = re.compile(r"auth\.(uid|jwt)\(\)|current_user|session_user|current_setting\(", re.I)

_PG_RLS = "https://www.postgresql.org/docs/current/ddl-rowsecurity.html"
_PG_POLICY = "https://www.postgresql.org/docs/current/sql-createpolicy.html"
_PG_VIEW = "https://www.postgresql.org/docs/current/sql-createview.html"
_PG_FUNC = "https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY"
_SUPABASE_RLS = "https://supabase.com/docs/guides/database/postgres/row-level-security"
_SUPABASE_LINTER = "https://supabase.com/docs/guides/database/database-linter"


def _ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _qname(schema: str, name: str) -> str:
    return f"{_ident(schema)}.{_ident(name)}"


def _role_list(roles) -> str:
    return ", ".join(_ident(r) for r in sorted(roles))


def _refs(provider: str, *urls: str) -> list[str]:
    extra = [_SUPABASE_RLS, _SUPABASE_LINTER] if provider == "supabase" else []
    return [*urls, *extra]


def _privileges_json(privs: dict[str, frozenset[str]]) -> dict[str, list[str]]:
    return {role: sorted(p) for role, p in sorted(privs.items())}


def _exposed(rel: Relation) -> dict[str, frozenset[str]]:
    return {role: p for role, p in rel.privileges.items() if p}


def _is_true(expr: str | None) -> bool:
    if expr is None:
        return False
    e = expr.strip().lower()
    while e.startswith("(") and e.endswith(")"):
        e = e[1:-1].strip()
    return e == "true"


def _gates(p: Policy) -> list[str]:
    """Expressions that actually gate the policy's operation (None = deny)."""
    if p.cmd == "INSERT":
        exprs = [p.with_check]
    elif p.cmd in ("SELECT", "DELETE"):
        exprs = [p.qual]
    else:  # UPDATE and ALL: a missing WITH CHECK inherits USING
        exprs = [p.qual, p.with_check or p.qual]
    return [e for e in exprs if e is not None]


def roles_bypassing_rls(snap: Snapshot, provider: str) -> Iterator[Finding]:
    for role in snap.roles:
        if not (role.superuser or role.bypass_rls):
            continue
        attr = "SUPERUSER" if role.superuser else "BYPASSRLS"
        yield Finding(
            rule_id="pg-role-bypass-rls",
            title="Audited role bypasses Row-Level Security",
            description=(
                f"Role {role.name} has the {attr} attribute: all RLS policies are ignored for "
                "it, so any request made with this role sees and modifies every row of the "
                "tables it can access."
            ),
            category=Category.DATABASE_PERMISSIONS,
            provider=provider,
            resource=f"role:{role.name}",
            severity=Severity.CRITICAL,
            confidence=Confidence.LIKELY,
            cwe="CWE-250",
            owasp="API5:2023",
            evidence={"superuser": role.superuser, "bypassrls": role.bypass_rls},
            remediation=Remediation(
                summary="Remove privileged attributes from roles used by application clients.",
                sql=f"ALTER ROLE {_ident(role.name)} NOSUPERUSER NOBYPASSRLS;",
                references=_refs(provider, _PG_RLS),
            ),
        )


def rls_disabled(snap: Snapshot, provider: str) -> Iterator[Finding]:
    for rel in snap.relations:
        if rel.kind not in TABLE_KINDS or rel.rls_enabled or not (exposed := _exposed(rel)):
            continue
        writes = any(p & WRITE for p in exposed.values())
        ignored = [p.name for p in snap.policies if (p.schema, p.table) == (rel.schema, rel.name)]
        q = _qname(rel.schema, rel.name)
        yield Finding(
            rule_id="pg-rls-disabled",
            title="RLS disabled on an accessible table"
            + (" (existing policies are ignored)" if ignored else ""),
            description=(
                f"{rel.qualified} doesn't have Row-Level Security enabled and the audited roles have "
                "effective privileges on it: any request with those roles reaches every row, with no "
                "filter by user or organization."
                + (" The defined policies have no effect while RLS is disabled." if ignored else "")
            ),
            category=Category.DATABASE_PERMISSIONS,
            provider=provider,
            resource=rel.qualified,
            severity=Severity.CRITICAL if writes else Severity.HIGH,
            confidence=Confidence.LIKELY,
            cwe="CWE-862",
            owasp="API1:2023",
            evidence={"privileges": _privileges_json(exposed), "ignored_policies": ignored},
            remediation=Remediation(
                summary=(
                    "Enable RLS and create policies that restrict each operation to the record's owner "
                    "or organization. If the table shouldn't be accessible, revoke the privileges."
                ),
                sql=f"ALTER TABLE {q} ENABLE ROW LEVEL SECURITY;\n-- or, if it shouldn't be exposed:\n"
                f"REVOKE ALL ON TABLE {q} FROM {_role_list(exposed)};",
                references=_refs(provider, _PG_RLS),
            ),
        )


def rls_owner_bypass(snap: Snapshot, provider: str) -> Iterator[Finding]:
    for rel in snap.relations:
        if rel.kind not in TABLE_KINDS or not rel.rls_enabled or rel.rls_forced or not rel.owned_by:
            continue
        q = _qname(rel.schema, rel.name)
        yield Finding(
            rule_id="pg-rls-owner-bypass",
            title="RLS ineffective for the table owner",
            description=(
                f"{rel.qualified} has RLS enabled, but it's owned by {rel.owner}, and the audited roles "
                f"{', '.join(sorted(rel.owned_by))} inherit that ownership. Owners bypass RLS unless "
                "FORCE ROW LEVEL SECURITY is active, so the policies don't apply to them."
            ),
            category=Category.DATABASE_PERMISSIONS,
            provider=provider,
            resource=rel.qualified,
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            cwe="CWE-863",
            owasp="API1:2023",
            evidence={"owner": rel.owner, "audited_roles_owning": sorted(rel.owned_by)},
            remediation=Remediation(
                summary=(
                    "Force RLS for the owner, or transfer ownership to a role the application doesn't "
                    "use at runtime."
                ),
                sql=f"ALTER TABLE {q} FORCE ROW LEVEL SECURITY;",
                references=_refs(provider, _PG_RLS),
            ),
        )


def permissive_policies(snap: Snapshot, provider: str) -> Iterator[Finding]:
    rels = {(r.schema, r.name): r for r in snap.relations}
    for p in snap.policies:
        rel = rels.get((p.schema, p.table))
        # With RLS disabled the policies don't apply; rls_disabled covers that case.
        if rel is None or not rel.rls_enabled or not p.permissive:
            continue
        needed = CMD_PRIVILEGES[p.cmd]
        affected = {
            role: privs & needed
            for role, privs in rel.privileges.items()
            if (role in p.roles or "public" in p.roles) and privs & needed
        }
        gates = _gates(p)
        if not affected or not gates:
            continue

        writes = any(privs & WRITE for privs in affected.values())
        restrictive = [
            r.name for r in snap.policies
            if (r.schema, r.table) == (p.schema, p.table) and not r.permissive
            and ("ALL" in (r.cmd, p.cmd) or r.cmd == p.cmd)
            and ("public" in r.roles or set(r.roles) & affected.keys())
        ]
        evidence = {
            "policy": p.name, "command": p.cmd, "policy_roles": list(p.roles),
            "using": p.qual, "with_check": p.with_check, "privileges": _privileges_json(affected),
        }
        if restrictive:
            evidence["restrictive_policies"] = restrictive
        common = dict(
            category=Category.DATABASE_PERMISSIONS,
            provider=provider,
            resource=f"{rel.qualified} [policy {p.name}]",
            owasp="API1:2023",
            evidence=evidence,
        )

        if any(_is_true(e) for e in gates):
            yield Finding(
                rule_id="pg-policy-unrestricted",
                title="Policy grants unrestricted access",
                description=(
                    f"Policy {p.name} on {rel.qualified} ({p.cmd}) uses an always-true condition "
                    f"for {', '.join(sorted(affected))}: every row becomes accessible to those roles."
                    + ("" if writes else " May be intentional for public data; confirm the intent.")
                    + (" There are restrictive policies that may limit the effect." if restrictive else "")
                ),
                severity=Severity.HIGH if writes else Severity.MEDIUM,
                confidence=Confidence.LIKELY if writes and not restrictive else Confidence.POSSIBLE,
                cwe="CWE-863",
                remediation=Remediation(
                    summary="Replace the condition with one that ties the row to the user or organization making the request.",
                    sql=f"ALTER POLICY {_ident(p.name)} ON {_qname(p.schema, p.table)}\n"
                    "  USING (owner_id = (SELECT auth.uid()));  -- adjust to the ownership column",
                    references=_refs(provider, _PG_POLICY),
                ),
                **common,
            )
        elif writes and not any(_IDENTITY.search(e) for e in gates):
            yield Finding(
                rule_id="pg-policy-no-ownership",
                title="Write policy with no ownership restriction",
                description=(
                    f"Policy {p.name} on {rel.qualified} ({p.cmd}) doesn't reference the identity of the "
                    "requester: a user can modify records belonging to other users or organizations that "
                    "satisfy the condition."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.POSSIBLE,
                cwe="CWE-639",
                remediation=Remediation(
                    summary=(
                        "Add an ownership check to the condition (e.g. owner_id = auth.uid()) or an "
                        "organization-membership check."
                    ),
                    references=_refs(provider, _PG_POLICY),
                ),
                **common,
            )


def exposed_views(snap: Snapshot, provider: str) -> Iterator[Finding]:
    for rel in snap.relations:
        readers = sorted(r for r, privs in rel.privileges.items() if "SELECT" in privs)
        if not readers:
            continue
        q = _qname(rel.schema, rel.name)
        common = dict(
            category=Category.DATABASE_PERMISSIONS,
            provider=provider,
            resource=rel.qualified,
            severity=Severity.MEDIUM,
            confidence=Confidence.POSSIBLE,
            cwe="CWE-863",
            owasp="API1:2023",
            evidence={"owner": rel.owner, "readers": readers},
        )
        if rel.kind == "view" and not rel.security_invoker:
            yield Finding(
                rule_id="pg-view-definer",
                title="View runs with the owner's privileges",
                description=(
                    f"{rel.qualified} doesn't use security_invoker: the underlying tables are read with "
                    f"{rel.owner}'s privileges, and their RLS isn't evaluated for whoever queries it "
                    f"({', '.join(readers)})."
                ),
                remediation=Remediation(
                    summary="Make the view honor the querying user's permissions (PostgreSQL 15+).",
                    sql=f"ALTER VIEW {q} SET (security_invoker = true);",
                    references=_refs(provider, _PG_VIEW),
                ),
                **common,
            )
        elif rel.kind == "materialized_view":
            yield Finding(
                rule_id="pg-matview-exposed",
                title="Materialized view accessible without RLS",
                description=(
                    f"{rel.qualified} is a materialized view readable by {', '.join(readers)}. "
                    "Materialized views don't support RLS: the entire content is visible to those roles."
                ),
                remediation=Remediation(
                    summary="Revoke direct access and expose the data through a view or function that filters by user.",
                    sql=f"REVOKE SELECT ON {q} FROM {_role_list(readers)};",
                    references=_refs(provider, _PG_RLS),
                ),
                **common,
            )


def security_definer_functions(snap: Snapshot, provider: str) -> Iterator[Finding]:
    for fn in snap.security_definer_functions:
        if not fn.executable_by:
            continue
        callers = sorted(fn.executable_by)
        sig = f"{_qname(fn.schema, fn.name)}({fn.args})"
        evidence = {"owner": fn.owner, "executable_by": callers, "search_path_set": fn.search_path_set}
        yield Finding(
            rule_id="pg-func-secdef-exposed",
            title="SECURITY DEFINER function executable by exposed roles",
            description=(
                f"{fn.signature} runs with {fn.owner}'s privileges and can be called by "
                f"{', '.join(callers)}. Without explicit authorization checks in its body, it bypasses RLS."
            ),
            category=Category.DATABASE_PERMISSIONS,
            provider=provider,
            resource=fn.signature,
            severity=Severity.MEDIUM,
            confidence=Confidence.POSSIBLE,
            cwe="CWE-250",
            owasp="API5:2023",
            evidence=evidence,
            remediation=Remediation(
                summary=(
                    "Use SECURITY INVOKER when possible; otherwise, validate identity inside the function "
                    "and restrict who can execute it."
                ),
                sql=f"REVOKE EXECUTE ON FUNCTION {sig} FROM PUBLIC, {_role_list(callers)};",
                references=_refs(provider, _PG_FUNC),
            ),
        )
        if not fn.search_path_set:
            yield Finding(
                rule_id="pg-func-search-path",
                title="SECURITY DEFINER function without a fixed search_path",
                description=(
                    f"{fn.signature} doesn't set search_path: objects created in an earlier schema on "
                    "the search path can hijack name resolution and run code with "
                    f"{fn.owner}'s privileges."
                ),
                category=Category.DATABASE_PERMISSIONS,
                provider=provider,
                resource=fn.signature,
                severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY,
                cwe="CWE-426",
                owasp="API5:2023",
                evidence=evidence,
                remediation=Remediation(
                    summary="Fix the search_path and qualify the objects used in the function body.",
                    sql=f"ALTER FUNCTION {sig} SET search_path = '';",
                    references=_refs(provider, _PG_FUNC),
                ),
            )


RULES = (
    roles_bypassing_rls,
    rls_disabled,
    rls_owner_bypass,
    permissive_policies,
    exposed_views,
    security_definer_functions,
)


def analyze(snap: Snapshot, provider: str) -> list[Finding]:
    unique = {f.fingerprint: f for rule in RULES for f in rule(snap, provider)}
    return sorted(unique.values(), key=lambda f: (f.severity.rank, f.rule_id, f.resource))
