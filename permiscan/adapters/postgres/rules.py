"""Regras estáticas sobre o snapshot do catálogo PostgreSQL.

Toda regra cruza a configuração com os privilégios efetivos dos papéis
auditados: uma policy permissiva ou um RLS desabilitado só vira finding quando
algum papel exposto consegue de fato exercer a operação.
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

# Referências que vinculam a expressão à identidade de quem faz a requisição.
# ponytail: heurística textual; funções auxiliares (ex.: is_member()) geram
# falso positivo, por isso os findings dela saem com confiança "possible".
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
    """Expressões que de fato controlam a operação da policy (None = nega)."""
    if p.cmd == "INSERT":
        exprs = [p.with_check]
    elif p.cmd in ("SELECT", "DELETE"):
        exprs = [p.qual]
    else:  # UPDATE e ALL: WITH CHECK ausente herda o USING
        exprs = [p.qual, p.with_check or p.qual]
    return [e for e in exprs if e is not None]


def roles_bypassing_rls(snap: Snapshot, provider: str) -> Iterator[Finding]:
    for role in snap.roles:
        if not (role.superuser or role.bypass_rls):
            continue
        attr = "SUPERUSER" if role.superuser else "BYPASSRLS"
        yield Finding(
            rule_id="pg-role-bypass-rls",
            title="Papel auditado ignora Row-Level Security",
            description=(
                f"O papel {role.name} possui o atributo {attr}: todas as policies de RLS são "
                "ignoradas para ele, então qualquer requisição feita com esse papel enxerga e altera "
                "todas as linhas das tabelas a que tem acesso."
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
                summary="Remova os atributos privilegiados de papéis usados por clientes da aplicação.",
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
            title="RLS desabilitado em tabela acessível"
            + (" (policies existentes são ignoradas)" if ignored else ""),
            description=(
                f"{rel.qualified} não tem Row-Level Security habilitado e os papéis auditados possuem "
                "privilégios efetivos sobre ela: qualquer requisição com esses papéis alcança todas as "
                "linhas, sem filtro por usuário ou organização."
                + (" As policies definidas não têm efeito enquanto o RLS estiver desabilitado." if ignored else "")
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
                    "Habilite o RLS e crie policies que restrinjam cada operação ao dono do registro ou "
                    "à sua organização. Se a tabela não deve ser acessível, revogue os privilégios."
                ),
                sql=f"ALTER TABLE {q} ENABLE ROW LEVEL SECURITY;\n-- ou, se não deve ser exposta:\n"
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
            title="RLS ineficaz para o dono da tabela",
            description=(
                f"{rel.qualified} tem RLS habilitado, mas pertence a {rel.owner}, e os papéis auditados "
                f"{', '.join(sorted(rel.owned_by))} herdam essa propriedade. Donos ignoram o RLS a menos "
                "que FORCE ROW LEVEL SECURITY esteja ativo, então as policies não se aplicam a eles."
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
                    "Force o RLS para o dono ou transfira a propriedade para um papel que a aplicação "
                    "não usa em tempo de execução."
                ),
                sql=f"ALTER TABLE {q} FORCE ROW LEVEL SECURITY;",
                references=_refs(provider, _PG_RLS),
            ),
        )


def permissive_policies(snap: Snapshot, provider: str) -> Iterator[Finding]:
    rels = {(r.schema, r.name): r for r in snap.relations}
    for p in snap.policies:
        rel = rels.get((p.schema, p.table))
        # Com RLS desabilitado as policies não valem; rls_disabled cobre o caso.
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
                title="Policy concede acesso irrestrito",
                description=(
                    f"A policy {p.name} em {rel.qualified} ({p.cmd}) usa uma condição sempre verdadeira "
                    f"para {', '.join(sorted(affected))}: todas as linhas ficam acessíveis a esses papéis."
                    + ("" if writes else " Pode ser intencional para dados públicos; confirme a intenção.")
                    + (" Há policies restritivas que podem limitar o efeito." if restrictive else "")
                ),
                severity=Severity.HIGH if writes else Severity.MEDIUM,
                confidence=Confidence.LIKELY if writes and not restrictive else Confidence.POSSIBLE,
                cwe="CWE-863",
                remediation=Remediation(
                    summary="Substitua a condição por uma que vincule a linha ao usuário ou à organização da requisição.",
                    sql=f"ALTER POLICY {_ident(p.name)} ON {_qname(p.schema, p.table)}\n"
                    "  USING (owner_id = (SELECT auth.uid()));  -- ajuste à coluna de propriedade",
                    references=_refs(provider, _PG_POLICY),
                ),
                **common,
            )
        elif writes and not any(_IDENTITY.search(e) for e in gates):
            yield Finding(
                rule_id="pg-policy-no-ownership",
                title="Policy de escrita sem restrição de propriedade",
                description=(
                    f"A policy {p.name} em {rel.qualified} ({p.cmd}) não referencia a identidade de quem "
                    "faz a requisição: um usuário pode alterar registros de outros usuários ou organizações "
                    "que satisfaçam a condição."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.POSSIBLE,
                cwe="CWE-639",
                remediation=Remediation(
                    summary=(
                        "Inclua na condição a verificação de propriedade (ex.: owner_id = auth.uid()) ou de "
                        "pertencimento à organização."
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
                title="View executa com privilégios do dono",
                description=(
                    f"{rel.qualified} não usa security_invoker: as tabelas subjacentes são lidas com os "
                    f"privilégios de {rel.owner}, e o RLS delas não é avaliado para quem consulta "
                    f"({', '.join(readers)})."
                ),
                remediation=Remediation(
                    summary="Faça a view respeitar as permissões de quem consulta (PostgreSQL 15+).",
                    sql=f"ALTER VIEW {q} SET (security_invoker = true);",
                    references=_refs(provider, _PG_VIEW),
                ),
                **common,
            )
        elif rel.kind == "materialized_view":
            yield Finding(
                rule_id="pg-matview-exposed",
                title="View materializada acessível sem RLS",
                description=(
                    f"{rel.qualified} é uma view materializada legível por {', '.join(readers)}. Views "
                    "materializadas não suportam RLS: todo o conteúdo fica visível a esses papéis."
                ),
                remediation=Remediation(
                    summary="Revogue o acesso direto e exponha os dados por uma view ou função que filtre por usuário.",
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
            title="Função SECURITY DEFINER executável por papéis expostos",
            description=(
                f"{fn.signature} executa com os privilégios de {fn.owner} e pode ser chamada por "
                f"{', '.join(callers)}. Sem validação explícita de autorização no corpo, ela contorna o RLS."
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
                    "Use SECURITY INVOKER quando possível; caso contrário, valide a identidade dentro da "
                    "função e restrinja quem pode executá-la."
                ),
                sql=f"REVOKE EXECUTE ON FUNCTION {sig} FROM PUBLIC, {_role_list(callers)};",
                references=_refs(provider, _PG_FUNC),
            ),
        )
        if not fn.search_path_set:
            yield Finding(
                rule_id="pg-func-search-path",
                title="Função SECURITY DEFINER sem search_path fixo",
                description=(
                    f"{fn.signature} não define search_path: objetos criados em um schema anterior no "
                    "caminho de busca podem sequestrar a resolução de nomes e executar código com os "
                    f"privilégios de {fn.owner}."
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
                    summary="Fixe o search_path e qualifique os objetos usados no corpo da função.",
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
