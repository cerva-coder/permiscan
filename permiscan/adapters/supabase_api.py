"""Varredura externa (caixa-preta) de um projeto Supabase pela Data API.

Usa só a URL do projeto e a chave anon — ambas públicas por design, embarcadas em qualquer
frontend. Observamos o que uma requisição anônima de fato consegue fazer, que é exatamente a
superfície que um cliente não autenticado alcança.

Modos de prova (todos opcionais, cada um com sua flag na CLI):
- leitura (padrão): lê uma amostra de linhas como anônimo;
- escrita (`--probe-writes`): tenta `POST` para ver se o anon consegue inserir;
- RPC (`--probe-rpc`): chama funções RPC para ver se respondem sem autenticação.

Testes de escrita e de RPC alteram o alvo; use-os só onde você tem autorização. Funções de
nome destrutivo (delete/drop/admin/…) não são chamadas sem `--include-destructive`.
"""

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from permiscan.adapters.base import AdapterError
from permiscan.findings import Category, Confidence, Finding, Remediation, Severity
from permiscan.sensitivity import most_sensitive

_DOCS_RLS = "https://supabase.com/docs/guides/database/postgres/row-level-security"
_DOCS_KEYS = "https://supabase.com/docs/guides/api/api-keys"
_TIMEOUT = 15

# ---- Detecção de credenciais (o que o content script da extensão faz) -------

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_SB_CLOUD_URL = re.compile(r"https://[a-z0-9-]+\.supabase\.co", re.I)
_SB_URL_ASSIGN = re.compile(r"""supabase[_-]?url["'\s:=]+(https://[^\s"'`,}\\]+)""", re.I)
# Chaves novas do Supabase (não-JWT): sb_publishable_… e sb_secret_…
_SB_KEY = re.compile(r"sb_(?:publishable|secret)_[A-Za-z0-9_-]{8,}")

# ---- Classificação de risco de RPC pelo nome -------------------------------

# Tokens em nomes snake_case; sem \b final porque '_' conta como caractere de palavra.
_RPC_DESTRUCTIVE = re.compile(r"delete|remove|drop|truncate|reset|revoke|grant|admin|purge|wipe|disable", re.I)
_RPC_WRITE = re.compile(r"update|modify|\bset|send|email|insert|create|upsert|approve|charge|pay", re.I)
_RPC_READ = re.compile(r"\b(get|list|fetch|check|validate|verify|count|search)|is_|has_", re.I)


def rpc_risk(name: str) -> Severity:
    if _RPC_DESTRUCTIVE.search(name):
        return Severity.CRITICAL
    if _RPC_WRITE.search(name):
        return Severity.HIGH
    if _RPC_READ.search(name):
        return Severity.MEDIUM
    return Severity.LOW


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


def _project_ref(url: str) -> str | None:
    m = re.match(r"https://([a-z0-9-]+)\.supabase\.co", url, re.I)
    return m.group(1) if m else None


@dataclass
class DetectedInstance:
    url: str
    keys: list[dict] = field(default_factory=list)  # {key, role, ref}

    @property
    def anon_key(self) -> str | None:
        for k in self.keys:
            if k.get("role") in ("anon", "publishable"):
                return k["key"]
        return self.keys[0]["key"] if self.keys else None


def _describe_key(key: str) -> dict:
    if key.startswith("sb_secret_"):
        return {"key": key, "role": "service_role", "ref": None}
    if key.startswith("sb_publishable_"):
        return {"key": key, "role": "publishable", "ref": None}
    claims = jwt_claims(key)
    return {"key": key, "role": claims.get("role", "desconhecido"), "ref": claims.get("ref")}


def detect_instances(text: str) -> list[DetectedInstance]:
    """Extrai URLs de projeto e chaves de um texto (HTML, bundle JS, .env…),
    emparelhando por project ref quando o JWT o informa."""
    urls = {u.rstrip("/").lower() for u in _SB_CLOUD_URL.findall(text)}
    urls |= {m.rstrip("/").lower() for m in _SB_URL_ASSIGN.findall(text)}
    
    # Filtra URLs óbvias de código morto ou placeholders
    invalid_refs = {"undefined", "null", "your-project", "example", "placeholder", "test"}
    urls = {u for u in urls if not any(ref in u for ref in invalid_refs)}

    keys = []
    for token in set(_JWT.findall(text)):
        claims = jwt_claims(token)
        # Tolerância maior: aceita JWTs com estrutura Supabase típica mesmo sem iss explícito
        if (claims.get("iss") == "supabase" or 
            claims.get("role") in ("anon", "service_role", "authenticated") or
            (claims.get("aud") and claims.get("ref"))):
            keys.append(_describe_key(token))
    keys += [_describe_key(k) for k in set(_SB_KEY.findall(text))]

    instances = {u: DetectedInstance(u) for u in urls}
    unpaired = []
    for k in keys:
        matched = [u for u in instances if k["ref"] and _project_ref(u) == k["ref"]]
        if matched:
            instances[matched[0]].keys.append(k)
        else:
            unpaired.append(k)
    # Chaves sem ref casável: associa à primeira URL se houver apenas uma
    if unpaired and len(instances) == 1:
        next(iter(instances.values())).keys.extend(unpaired)
    # Se múltiplas URLs e chaves sem ref, não distribui (evita falsos positivos)
    # Só distribui se a chave for do tipo sb_* (sem ref no JWT)
    elif unpaired and len(instances) > 1:
        sb_keys = [k for k in unpaired if k["key"].startswith("sb_")]
        for k in sb_keys:
            for inst in instances.values():
                inst.keys.append(k)
    return list(instances.values())


def fetch_text(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        raise AdapterError("a URL deve começar com http:// ou https://")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 (esquema validado)
            return resp.read(5_000_000).decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        raise AdapterError(f"falha ao buscar {url}: {getattr(e, 'reason', e)}") from None


# ---- Scanner ---------------------------------------------------------------


@dataclass
class ApiScanOptions:
    rows: int = 1
    probe_writes: bool = False
    probe_rpc: bool = False
    include_destructive: bool = False


@dataclass(frozen=True)
class ApiTable:
    name: str
    columns: tuple[str, ...]
    row_count: int | None
    sample: list[dict] = field(default_factory=list)


def _truncate(value: Any) -> Any:
    if isinstance(value, str) and len(value) > 40:
        return value[:40] + "…"
    if isinstance(value, (dict, list)):
        return "[obj]"
    return value


class SupabaseApiScanner:
    provider = "supabase-api"

    def __init__(self, base_url: str, anon_key: str, options: ApiScanOptions | None = None):
        if not base_url.startswith(("http://", "https://")):
            raise AdapterError("a URL do projeto deve começar com http:// ou https://")
        self.base_url = base_url.rstrip("/")
        self.key = anon_key
        self.options = options or ApiScanOptions()
        self.rest = f"{self.base_url}/rest/v1"

    # --- HTTP ---------------------------------------------------------------

    def _request(self, path, *, method="GET", headers=None, data=None):
        req = urllib.request.Request(
            f"{self.rest}{path}", method=method, data=data,
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
            raise AdapterError("chave rejeitada (HTTP 401): verifique a chave e a URL do projeto")
        if status != 200:
            raise AdapterError(f"OpenAPI indisponível em {self.rest}/ (HTTP {status})")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise AdapterError("resposta do OpenAPI não é JSON; a URL aponta para um projeto Supabase?") from None

    # --- Descoberta / probes ------------------------------------------------

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

    def _probe_table(self, name: str, rows: int) -> ApiTable | None:
        """Lê até `rows` linhas como anônimo. None = anon não consegue ler."""
        rows = max(1, rows)
        status, headers, body = self._request(
            f"/{name}?limit={rows}", headers={"Prefer": "count=exact", "Range-Unit": "items", "Range": f"0-{rows - 1}"}
        )
        if status not in (200, 206):
            return None
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, list):
            return None
        count = None
        rng = headers.get("Content-Range", "")
        if "/" in rng and rng.rsplit("/", 1)[1].isdigit():
            count = int(rng.rsplit("/", 1)[1])
        if not data and not count:
            return None  # vazia ou RLS ativo: não é finding
        columns = tuple(data[0].keys()) if data else ()
        sample = [{k: _truncate(v) for k, v in row.items()} for row in data[:5]]
        return ApiTable(name, columns, count, sample)

    def _test_write(self, name: str) -> str:
        """'inserted' | 'allowed' (passou do RLS, barrou em constraint) | 'blocked' | 'unknown'."""
        status, _, body = self._request(
            f"/{name}", method="POST", data=b"{}",
            headers={"Content-Type": "application/json", "Prefer": "return=minimal"},
        )
        low = body.decode(errors="replace").lower()
        if status in (200, 201, 204):
            return "inserted"
        if status in (401, 403) or re.search(r"row-level security|policy|permission|not authoriz|jwt", low):
            return "blocked"
        if status in (400, 409):  # erro de dados/constraint => o RLS deixou passar
            return "allowed"
        return "unknown"

    def _test_rpc(self, name: str) -> str:
        """'accessible' | 'blocked' | 'unknown'."""
        status, _, body = self._request(
            f"/rpc/{name}", method="POST", data=b"{}", headers={"Content-Type": "application/json"}
        )
        low = body.decode(errors="replace").lower()
        if status in (200, 204, 206):
            return "accessible"
        if status in (401, 403) or re.search(r"permission|not authoriz|jwt|policy", low):
            return "blocked"
        if re.search(r"could not find|does not exist|not found", low):
            return "unknown"
        if status == 400 or re.search(r"requir|missing|argument|parameter|expected|without parameters", low):
            return "accessible"  # existe e respondeu; só faltam argumentos
        return "unknown"

    # --- Interface ----------------------------------------------------------

    def check(self) -> dict[str, Any]:
        claims = jwt_claims(self.key)
        tables, rpcs = self._tables_and_rpcs(self._openapi())
        return {
            "provider": self.provider,
            "target": self.base_url,
            "project_ref": claims.get("ref") or _project_ref(self.base_url),
            "key_role": claims.get("role") or ("service_role" if self.key.startswith("sb_secret_") else "desconhecido"),
            "exposed_tables": len(tables),
            "exposed_rpc_functions": len(rpcs),
            "rpc_functions": [{"name": n, "risk": rpc_risk(n).value} for n in rpcs],
        }

    def scan(self) -> list[Finding]:
        opt = self.options
        claims = jwt_claims(self.key)
        findings: list[Finding] = []

        if claims.get("role") == "service_role" or self.key.startswith("sb_secret_"):
            findings.append(self._service_role_finding(claims))

        tables, rpcs = self._tables_and_rpcs(self._openapi())

        for name in tables:
            table = self._probe_table(name, opt.rows)
            if table is None:
                continue
            findings.append(self._read_finding(table))
            if opt.probe_writes:
                result = self._test_write(name)
                if result in ("inserted", "allowed"):
                    findings.append(self._write_finding(name, result))

        if opt.probe_rpc:
            for name in rpcs:
                risk = rpc_risk(name)
                if risk == Severity.CRITICAL and not opt.include_destructive:
                    findings.append(self._rpc_skipped_finding(name))
                    continue
                if self._test_rpc(name) == "accessible":
                    findings.append(self._rpc_finding(name, risk))

        return sorted(findings, key=lambda f: (f.severity.rank, f.rule_id, f.resource))

    # --- Construtores de finding -------------------------------------------

    def _service_role_finding(self, claims: dict) -> Finding:
        return Finding(
            rule_id="supabase-service-role-key",
            title="Chave service_role em uso no cliente",
            description=(
                "A chave fornecida ignora todo o RLS e dá acesso total à Data API. Se foi obtida de um "
                "frontend ou de código público, é uma exposição crítica; ela nunca deve sair do servidor."
            ),
            category=Category.AUTHENTICATION, provider=self.provider,
            resource=f"project:{claims.get('ref') or _project_ref(self.base_url) or self.base_url}",
            severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED, cwe="CWE-200", owasp="API2:2023",
            evidence={"role": "service_role", "ref": claims.get("ref")},
            remediation=Remediation(
                summary="Revogue/rotacione a chave e use apenas a chave anon/publishable no cliente.",
                references=[_DOCS_KEYS]),
        )

    def _read_finding(self, table: ApiTable) -> Finding:
        severity, flagged = most_sensitive(list(table.columns))
        if severity == Severity.INFO:
            severity = Severity.MEDIUM
        return Finding(
            rule_id="supabase-api-anon-read",
            title="Tabela legível por requisição anônima",
            description=(
                f"A tabela '{table.name}' retornou dados para uma requisição anônima pela Data API: o RLS "
                "está desabilitado ou há policy que libera o papel anon. Confirme se o acesso público é "
                "intencional; se não for, é exposição de dados sem autenticação."
                + (f" Colunas sensíveis pelo nome: {', '.join(flagged)}." if flagged else "")
            ),
            category=Category.AUTHORIZATION, provider=self.provider, resource=f"rest/v1/{table.name}",
            severity=severity, confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API1:2023",
            evidence={"columns": list(table.columns), "row_count": table.row_count,
                      "sensitive_columns": flagged, "sample": table.sample, "observed_as": "anon"},
            remediation=Remediation(
                summary="Habilite o RLS e crie policies que exijam autenticação e propriedade; se não deve ser "
                "pública, revogue o acesso do papel anon.",
                sql=f'ALTER TABLE "{table.name}" ENABLE ROW LEVEL SECURITY;', references=[_DOCS_RLS]),
        )

    def _write_finding(self, name: str, result: str) -> Finding:
        inserted = result == "inserted"
        return Finding(
            rule_id="supabase-api-anon-write",
            title="Tabela gravável por requisição anônima",
            description=(
                f"Uma requisição anônima de escrita (POST) em '{name}' "
                + ("inseriu uma linha: " if inserted else "passou pelo RLS e só foi barrada por uma restrição de "
                   "dados (NOT NULL/constraint): ")
                + "o papel anon consegue escrever sem autenticação."
            ),
            category=Category.AUTHORIZATION, provider=self.provider, resource=f"rest/v1/{name}",
            severity=Severity.CRITICAL if inserted else Severity.HIGH,
            confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API1:2023",
            evidence={"probe": "POST {}", "result": result, "observed_as": "anon"},
            remediation=Remediation(
                summary="Habilite o RLS e crie policy de INSERT que exija autenticação e propriedade; revogue "
                "INSERT/UPDATE/DELETE do papel anon se a escrita não deve ser pública.",
                references=[_DOCS_RLS]),
        )

    def _rpc_finding(self, name: str, risk: Severity) -> Finding:
        return Finding(
            rule_id="supabase-api-anon-rpc",
            title="Função RPC chamável por requisição anônima",
            description=(
                f"A função '{name}' respondeu a uma chamada anônima (POST /rpc/{name}) sem exigir "
                "autenticação. O risco vem do que a função faz; o nome sugere severidade "
                f"{risk.value}. Confirme se a exposição é intencional e se a função valida a identidade."
            ),
            category=Category.AUTHORIZATION, provider=self.provider, resource=f"rest/v1/rpc/{name}",
            severity=risk if risk.rank < Severity.MEDIUM.rank else Severity.MEDIUM,
            confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API5:2023",
            evidence={"probe": "POST {}", "risk_by_name": risk.value, "observed_as": "anon"},
            remediation=Remediation(
                summary="Restrinja a execução (REVOKE EXECUTE … FROM anon) ou valide auth.uid() dentro da "
                "função; exponha pela Data API só as funções que devem ser públicas.",
                references=[_DOCS_RLS]),
        )

    def _rpc_skipped_finding(self, name: str) -> Finding:
        return Finding(
            rule_id="supabase-api-rpc-exposed",
            title="Função RPC de nome destrutivo exposta (não chamada)",
            description=(
                f"A função '{name}' está exposta na Data API e o nome sugere efeito destrutivo. Não a chamei "
                "automaticamente para não alterar o alvo. Rode com --include-destructive para testá-la, "
                "de preferência em projeto próprio ou de teste."
            ),
            category=Category.AUTHORIZATION, provider=self.provider, resource=f"rest/v1/rpc/{name}",
            severity=Severity.INFO, confidence=Confidence.POSSIBLE, cwe="CWE-284", owasp="API5:2023",
            evidence={"risk_by_name": "critical", "tested": False},
            remediation=Remediation(
                summary="Confirme se essa função deve ser chamável pela API pública; se não, revogue EXECUTE do anon.",
                references=[_DOCS_RLS]),
        )
