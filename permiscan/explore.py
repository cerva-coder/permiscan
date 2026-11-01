"""Exploração ao vivo de um alvo salvo, reaproveitando os scanners existentes.

Tudo aqui é a MESMA superfície que o scanner já toca: lê o que a má-configuração do alvo
expõe ao anônimo (URL + chave pública já guardadas). Leitura é o padrão; escrita e a criação
de usuário sintético (para o teste diferencial de RLS) só acontecem sob flag explícita, com o
mesmo cuidado do CLI. Nada destrutivo, nada de bypass de autenticação.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

from permiscan.adapters.base import AdapterError
from permiscan.adapters.supabase_api import SupabaseApiScanner, rpc_risk
from permiscan.discovery import COMMON_COLLECTIONS

_TIMEOUT = 15
# Operadores PostgREST permitidos no query builder (evita injeção de sintaxe arbitrária).
_OPS = {"eq", "neq", "gt", "gte", "lt", "lte", "like", "ilike", "is", "in", "cs", "cd"}


def _get_json(url: str, headers: dict | None = None) -> tuple[int, object]:
    req = urllib.request.Request(url, headers={"User-Agent": "permiscan", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:  # noqa: S310
            body = r.read(5_000_000)
            status = r.status
    except urllib.error.HTTPError as e:
        body, status = e.read(5_000_000), e.code
    except urllib.error.URLError as e:
        raise AdapterError(f"falha ao buscar {url}: {e.reason}") from None
    try:
        return status, json.loads(body)
    except json.JSONDecodeError:
        return status, body.decode("utf-8", "replace")


def _require(target: dict, *fields: str) -> None:
    for f in fields:
        if not target.get(f):
            raise AdapterError(f"alvo sem '{f}' — não dá para explorar")


# --- Descoberta de recursos exploráveis -------------------------------------


def resources(target: dict) -> dict:
    plat = target["platform"]
    if plat == "supabase":
        _require(target, "url", "api_key")
        sc = SupabaseApiScanner(target["url"], target["api_key"])
        tables, rpcs = sc._tables_and_rpcs(sc._openapi())
        return {"kind": "supabase", "tables": tables,
                "rpcs": [{"name": n, "risk": rpc_risk(n).value} for n in rpcs]}
    if plat == "firebase":
        pid = target.get("project_ref")
        url = target.get("url") or ""
        return {"kind": "firebase", "project": pid,
                "collections": list(COMMON_COLLECTIONS),
                "rtdb": url if "firebaseio" in url or "firebasedatabase" in url else (
                    f"https://{pid}-default-rtdb.firebaseio.com" if pid else None),
                "bucket": (target.get("project_ref") and f"{pid}.appspot.com") or None}
    return {"kind": "none"}


# --- Leitura (read-only) -----------------------------------------------------


def supabase_rows(target: dict, table: str, *, select: str = "*", filters: list | None = None,
                  order: str | None = None, limit: int = 50, offset: int = 0) -> dict:
    _require(target, "url", "api_key")
    sc = SupabaseApiScanner(target["url"], target["api_key"])
    q = f"/{urllib.parse.quote(table)}?select={urllib.parse.quote(select, safe='*,')}"
    q += f"&limit={max(1, min(limit, 200))}&offset={max(0, offset)}"
    for f in filters or []:
        op = f.get("op", "eq")
        if op not in _OPS:
            raise AdapterError(f"operador não permitido: {op}")
        col = urllib.parse.quote(str(f["col"]))
        val = urllib.parse.quote(str(f.get("val", "")), safe="")
        q += f"&{col}={op}.{val}"
    if order:
        q += f"&order={urllib.parse.quote(order, safe='.,')}"
    status, headers, body = sc._request(q, headers={"Prefer": "count=exact"})
    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        rows = []
    count = None
    rng = headers.get("Content-Range", "")
    if "/" in rng and rng.rsplit("/", 1)[1].isdigit():
        count = int(rng.rsplit("/", 1)[1])
    return {"status": status, "count": count, "rows": rows if isinstance(rows, list) else [],
            "query": q}


def _flatten_firestore(fields: dict) -> dict:
    """{col:{stringValue:x}} -> {col:x}, pegando o primeiro tipo de cada campo."""
    out = {}
    for k, v in (fields or {}).items():
        out[k] = next(iter(v.values())) if isinstance(v, dict) and v else v
    return out


def firestore_docs(target: dict, collection: str, page: int = 25) -> dict:
    _require(target, "project_ref", "api_key")
    url = (f"https://firestore.googleapis.com/v1/projects/{target['project_ref']}"
           f"/databases/(default)/documents/{urllib.parse.quote(collection)}"
           f"?pageSize={max(1, min(page, 100))}&key={target['api_key']}")
    status, data = _get_json(url)
    docs = []
    if isinstance(data, dict):
        for d in data.get("documents", []):
            docs.append({"id": d.get("name", "").rsplit("/", 1)[-1], **_flatten_firestore(d.get("fields"))})
    return {"status": status, "rows": docs, "count": len(docs)}


def rtdb_get(target: dict, path: str = "") -> dict:
    base = target.get("url") or (target.get("project_ref") and
                                 f"https://{target['project_ref']}-default-rtdb.firebaseio.com")
    if not base:
        raise AdapterError("alvo sem URL de RTDB")
    path = path.strip("/")
    url = f"{base.rstrip('/')}/{path}.json" if path else f"{base.rstrip('/')}/.json?shallow=true"
    status, data = _get_json(url)
    return {"status": status, "data": data, "path": "/" + path}


def storage_list(target: dict, prefix: str = "") -> dict:
    pid = target.get("project_ref")
    if not pid:
        raise AdapterError("alvo sem bucket de Storage")
    bucket = f"{pid}.appspot.com"
    url = (f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
           f"?maxResults=100&prefix={urllib.parse.quote(prefix, safe='')}")
    status, data = _get_json(url)
    items = []
    if isinstance(data, dict):
        for it in data.get("items", []):
            items.append({"name": it.get("name"), "size": it.get("size"),
                          "contentType": it.get("contentType"), "updated": it.get("updated")})
    return {"status": status, "rows": items, "count": len(items), "bucket": bucket}


# --- Testes de autorização (gated) ------------------------------------------


def supabase_write_test(target: dict, table: str) -> dict:
    """Reusa o probe de escrita do scanner: POST {} — não destrutivo, inserção vazia."""
    _require(target, "url", "api_key")
    sc = SupabaseApiScanner(target["url"], target["api_key"])
    result = sc._test_write(table)  # 'inserted'|'allowed'|'blocked'|'unknown'
    return {"table": table, "result": result,
            "anon_can_write": result in ("inserted", "allowed")}


def _signup_token(target: dict) -> str | None:
    """Cria um usuário sintético no Supabase Auth e devolve o access_token (role authenticated).

    Intrusivo: cria conta no alvo. Só é chamado sob flag explícita (create_test_user)."""
    import secrets

    url = f"{target['url'].rstrip('/')}/auth/v1/signup"
    email = f"permiscan+{secrets.token_hex(6)}@example.com"
    data = json.dumps({"email": email, "password": secrets.token_urlsafe(16)}).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"apikey": target["api_key"], "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:  # noqa: S310
            body = json.loads(r.read(1_000_000))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read(1_000_000))
        except json.JSONDecodeError:
            return None
    except urllib.error.URLError:
        return None
    return body.get("access_token")


def supabase_diff(target: dict, table: str, *, create_test_user: bool = False) -> dict:
    """Compara o acesso de leitura a uma tabela entre identidades, para evidenciar falha de RLS.

    Sempre inclui 'anon' (chave pública). Se create_test_user=True, cria um usuário sintético e
    inclui 'authenticated' — isso cria uma conta no alvo, então fica atrás da flag."""
    _require(target, "url", "api_key")
    sc = SupabaseApiScanner(target["url"], target["api_key"])
    identities = [("anon", {})]
    note = None
    if create_test_user:
        token = _signup_token(target)
        if token:
            identities.append(("authenticated", {"Authorization": f"Bearer {token}"}))
        else:
            note = "não foi possível criar usuário sintético (signup fechado?); só 'anon' testado"

    out = {}
    for name, extra in identities:
        status, headers, body = sc._request(f"/{urllib.parse.quote(table)}?limit=1",
                                             headers={"Prefer": "count=exact", **extra})
        count = None
        rng = headers.get("Content-Range", "")
        if "/" in rng and rng.rsplit("/", 1)[1].isdigit():
            count = int(rng.rsplit("/", 1)[1])
        out[name] = {"status": status, "readable": status in (200, 206), "row_count": count}
    return {"table": table, "identities": out, "note": note}
