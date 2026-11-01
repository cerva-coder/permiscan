"""Varredura externa (caixa-preta) de um projeto Supabase pela Data API.

Usa só a URL do projeto e a chave anon — ambas públicas por design, embarcadas em
qualquer frontend. Observamos o que uma requisição anônima de fato consegue ler, que é
exatamente a superfície que um cliente não autenticado alcança.

Padrão somente leitura: lemos o OpenAPI e no máximo uma linha por tabela para descobrir as
colunas, guardando apenas a contagem e os nomes das colunas — nunca os valores. Escrita e
execução de RPC não acontecem aqui (ver IMPLEMENTATION_PLAN.md, M5).
"""

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from permiscan.adapters.base import AdapterError
from permiscan.findings import Category, Confidence, Finding, Remediation, Severity
from permiscan.sensitivity import most_sensitive

_DOCS_RLS = "https://supabase.com/docs/guides/database/postgres/row-level-security"
_DOCS_KEYS = "https://supabase.com/docs/guides/api/api-keys"
_TIMEOUT = 15


def _b64url_json(segment: str) -> dict | None:
    import base64

    try:
        pad = "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(segment + pad))
    except Exception:
        return None


def jwt_claims(token: str) -> dict:
    parts = token.split(".")
    return _b64url_json(parts[1]) or {} if len(parts) >= 2 else {}


@dataclass(frozen=True)
class ApiTable:
    name: str
    columns: tuple[str, ...]
    row_count: int | None  # None = contagem não informada pelo servidor


class SupabaseApiScanner:
    provider = "supabase-api"

    def __init__(self, base_url: str, anon_key: str):
        if not base_url.startswith(("http://", "https://")):
            raise AdapterError("a URL do projeto deve começar com http:// ou https://")
        self.base_url = base_url.rstrip("/")
        self.key = anon_key
        self.rest = f"{self.base_url}/rest/v1"

    # --- HTTP ---------------------------------------------------------------

    def _request(self, path: str, *, method: str = "GET", headers: dict | None = None) -> tuple[int, dict, bytes]:
        req = urllib.request.Request(
            f"{self.rest}{path}",
            method=method,
            headers={"apikey": self.key, "Authorization": f"Bearer {self.key}", "Accept": "application/json",
                     **(headers or {})},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 (esquema validado no __init__)
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()
        except urllib.error.URLError as e:
            raise AdapterError(f"falha ao conectar em {self.base_url}: {e.reason}") from None

    def _openapi(self) -> dict:
        status, _, body = self._request("/")
        if status == 401:
            raise AdapterError("chave anon rejeitada (HTTP 401): verifique a chave e a URL do projeto")
        if status != 200:
            raise AdapterError(f"OpenAPI indisponível em {self.rest}/ (HTTP {status})")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise AdapterError("resposta do OpenAPI não é JSON; a URL aponta para um projeto Supabase?") from None

    # --- Descoberta ---------------------------------------------------------

    @staticmethod
    def _tables_and_rpcs(spec: dict) -> tuple[list[str], list[str]]:
        tables, rpcs = [], []
        for path in spec.get("paths", {}):
            if path in ("/", "") or "{" in path:
                continue
            name = path.strip("/")
            if name.startswith("rpc/"):
                rpcs.append(name[len("rpc/"):])
            elif name and not name.startswith("_"):
                tables.append(name)
        return sorted(tables), sorted(rpcs)

    def _probe_table(self, name: str) -> ApiTable | None:
        """Lê no máximo 1 linha como anônimo. None = anon não consegue ler."""
        status, headers, body = self._request(
            f"/{name}?limit=1", headers={"Prefer": "count=exact", "Range-Unit": "items", "Range": "0-0"}
        )
        if status not in (200, 206):
            return None
        try:
            rows = json.loads(body)
        except json.JSONDecodeError:
            return None
        if not isinstance(rows, list):
            return None
        count = None
        rng = headers.get("Content-Range", "")
        if "/" in rng and rng.rsplit("/", 1)[1].isdigit():
            count = int(rng.rsplit("/", 1)[1])
        columns = tuple(rows[0].keys()) if rows else ()
        # Sem linhas e sem contagem: pode ser RLS ativo ou tabela vazia; não é finding.
        if not rows and not count:
            return None
        return ApiTable(name, columns, count)

    # --- Interface ----------------------------------------------------------

    def check(self) -> dict[str, Any]:
        claims = jwt_claims(self.key)
        spec = self._openapi()
        tables, rpcs = self._tables_and_rpcs(spec)
        return {
            "provider": self.provider,
            "target": self.base_url,
            "project_ref": claims.get("ref"),
            "key_role": claims.get("role", "desconhecido"),
            "exposed_tables": len(tables),
            "exposed_rpc_functions": len(rpcs),
        }

    def scan(self) -> list[Finding]:
        claims = jwt_claims(self.key)
        findings: list[Finding] = []

        if claims.get("role") == "service_role":
            findings.append(Finding(
                rule_id="supabase-service-role-key",
                title="Chave service_role em uso no cliente",
                description=(
                    "A chave fornecida tem role=service_role: ela ignora todo o RLS e dá acesso total à "
                    "Data API. Se foi obtida de um frontend ou de código público, é uma exposição crítica; "
                    "ela nunca deve sair do servidor."
                ),
                category=Category.AUTHENTICATION,
                provider=self.provider,
                resource=f"project:{claims.get('ref', self.base_url)}",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                cwe="CWE-200",
                owasp="API2:2023",
                evidence={"role": "service_role", "ref": claims.get("ref")},
                remediation=Remediation(
                    summary="Revogue/rotacione a chave e use apenas a chave anon/publishable no cliente.",
                    references=[_DOCS_KEYS],
                ),
            ))

        tables, _ = self._tables_and_rpcs(self._openapi())
        for name in tables:
            table = self._probe_table(name)
            if table is None:
                continue
            severity, flagged = most_sensitive(list(table.columns))
            # Sem coluna sensível no nome, a exposição ainda é relevante, mas pode ser
            # dado público intencional: fica em medium para o usuário confirmar a intenção.
            if severity == Severity.INFO:
                severity = Severity.MEDIUM
            findings.append(Finding(
                rule_id="supabase-api-anon-read",
                title="Tabela legível por requisição anônima",
                description=(
                    f"A tabela '{table.name}' retornou dados para uma requisição anônima pela Data API: "
                    "o RLS está desabilitado ou há policy que libera o papel anon. Confirme se esse acesso "
                    "público é intencional; se não for, é exposição de dados sem autenticação."
                    + (f" Colunas sensíveis pelo nome: {', '.join(flagged)}." if flagged else "")
                ),
                category=Category.AUTHORIZATION,
                provider=self.provider,
                resource=f"rest/v1/{table.name}",
                severity=severity,
                confidence=Confidence.CONFIRMED,  # comportamento observado, não inferido
                cwe="CWE-284",
                owasp="API1:2023",
                evidence={
                    "columns": list(table.columns),
                    "row_count": table.row_count,
                    "sensitive_columns": flagged,
                    "observed_as": "anon",
                },
                remediation=Remediation(
                    summary=(
                        "Habilite o RLS e crie policies que exijam autenticação e propriedade; se a tabela "
                        "não deve ser pública, revogue o acesso do papel anon."
                    ),
                    sql=f'ALTER TABLE "{table.name}" ENABLE ROW LEVEL SECURITY;',
                    references=[_DOCS_RLS],
                ),
            ))

        return sorted(findings, key=lambda f: (f.severity.rank, f.rule_id, f.resource))
