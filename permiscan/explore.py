"""Live exploration of a saved target, reusing the existing scanners.

Everything here is the SAME surface the scanner already touches: it reads whatever the
target's misconfiguration exposes to anonymous (URL + public key already stored). Reads
are the default; writes and synthetic user creation (for the RLS differential test) only
happen under an explicit flag, with the same care as the CLI. Nothing destructive, no
authentication bypass.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

from permiscan.adapters.base import AdapterError
from permiscan.adapters.supabase_api import SupabaseApiScanner, rpc_risk
from permiscan.discovery import COMMON_COLLECTIONS

_TIMEOUT = 15
# PostgREST operators allowed in the query builder (avoids arbitrary syntax injection).
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
        raise AdapterError(f"failed to fetch {url}: {e.reason}") from None
    try:
        return status, json.loads(body)
    except json.JSONDecodeError:
        return status, body.decode("utf-8", "replace")


def _require(target: dict, *fields: str) -> None:
    for f in fields:
        if not target.get(f):
            raise AdapterError(f"target has no '{f}' — can't explore")


# --- Discovering explorable resources ---------------------------------------


def _evidence_by_rule(target: dict, rule_id: str) -> dict:
    for f in target.get("findings") or []:
        if f.get("rule_id") == rule_id:
            return f.get("evidence") or {}
    return {}


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
        # Collections/keys already confirmed by the scan (finding evidence) come first — direct
        # navigation with nothing to ask the user. COMMON_COLLECTIONS is only an extra suggestion.
        confirmed_cols = list(_evidence_by_rule(target, "firebase-firestore-public-read").get("collections", []))
        rtdb_ev = _evidence_by_rule(target, "firebase-rtdb-public-read")
        # The bucket name can NOT be reconstructed from the project_ref: Firebase projects
        # created after 2024 use "<project>.firebasestorage.app", not "<project>.appspot.com"
        # anymore. The original scan already confirmed the real name in the evidence —
        # reuse it, never guess again.
        storage_ev = _evidence_by_rule(target, "firebase-storage-public-list")
        return {"kind": "firebase", "project": pid,
                "collections": confirmed_cols or [],
                "collections_suggested": [c for c in COMMON_COLLECTIONS if c not in confirmed_cols],
                "rtdb_keys": rtdb_ev.get("top_level_keys", []),
                "rtdb": (bool(rtdb_ev) and (url if "firebaseio" in url or "firebasedatabase" in url else (
                    f"https://{pid}-default-rtdb.firebaseio.com" if pid else None))) or None,
                "bucket": storage_ev.get("bucket")}
    return {"kind": "none"}


# --- Reads (read-only) --------------------------------------------------------


def supabase_rows(target: dict, table: str, *, select: str = "*", filters: list | None = None,
                  order: str | None = None, limit: int = 50, offset: int = 0) -> dict:
    _require(target, "url", "api_key")
    sc = SupabaseApiScanner(target["url"], target["api_key"])
    q = f"/{urllib.parse.quote(table)}?select={urllib.parse.quote(select, safe='*,')}"
    q += f"&limit={max(1, min(limit, 200))}&offset={max(0, offset)}"
    for f in filters or []:
        op = f.get("op", "eq")
        if op not in _OPS:
            raise AdapterError(f"operator not allowed: {op}")
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
    """{col:{stringValue:x}} -> {col:x}, taking the first type of each field."""
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


def rtdb_get(target: dict, path: str = "", shallow: bool = True) -> dict:
    """shallow=True lists only this level's keys (navigation); False returns the full (leaf) value."""
    base = target.get("url") or (target.get("project_ref") and
                                 f"https://{target['project_ref']}-default-rtdb.firebaseio.com")
    if not base:
        raise AdapterError("target has no RTDB URL")
    path = path.strip("/")
    q = "?shallow=true" if shallow else ""
    url = f"{base.rstrip('/')}/{path}.json{q}"
    status, data = _get_json(url)
    return {"status": status, "data": data, "path": "/" + path, "shallow": shallow}


def storage_list(target: dict, prefix: str = "", bucket: str | None = None) -> dict:
    """Lists a "directory" of the bucket. `prefixes` are the virtual subfolders returned by the
    Firebase Storage API — that's what lets the user navigate without typing any path.

    `bucket` must come from the name already confirmed in `resources()`/evidence; never
    reconstructed from the project_ref — recent projects use "<project>.firebasestorage.app",
    not "<project>.appspot.com" anymore, and guessing silently fails (404) on newer projects.
    """
    pid = target.get("project_ref")
    bucket = bucket or _evidence_by_rule(target, "firebase-storage-public-list").get("bucket")
    if not bucket:
        if not pid:
            raise AdapterError("target has no Storage bucket")
        bucket = f"{pid}.appspot.com"  # no saved evidence (older target) — best guess available
    prefix = prefix.strip("/")
    qprefix = f"{prefix}/" if prefix else ""
    url = (f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
           f"?maxResults=200&delimiter=/&prefix={urllib.parse.quote(qprefix, safe='/')}")
    status, data = _get_json(url)
    items, prefixes = [], []
    if isinstance(data, dict):
        for it in data.get("items", []):
            items.append({"name": it.get("name"), "size": it.get("size"),
                          "contentType": it.get("contentType"), "updated": it.get("updated"),
                          "url": f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o/"
                                 f"{urllib.parse.quote(it.get('name', ''), safe='')}?alt=media"})
        prefixes = [p.rstrip("/") for p in data.get("prefixes", [])]
    return {"status": status, "rows": items, "prefixes": prefixes, "count": len(items),
            "bucket": bucket, "prefix": prefix}


# --- Authorization tests (gated) ---------------------------------------------


def supabase_write_test(target: dict, table: str) -> dict:
    """Reuses the scanner's write probe: POST {} — non-destructive, empty insert."""
    _require(target, "url", "api_key")
    sc = SupabaseApiScanner(target["url"], target["api_key"])
    result = sc._test_write(table)  # 'inserted'|'allowed'|'blocked'|'unknown'
    return {"table": table, "result": result,
            "anon_can_write": result in ("inserted", "allowed")}


def _signup_token(target: dict) -> str | None:
    """Creates a synthetic user in Supabase Auth and returns the access_token (authenticated role).

    Intrusive: creates an account on the target. Only called under an explicit flag (create_test_user)."""
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
    """Compares read access to a table across identities, to evidence an RLS failure.

    Always includes 'anon' (public key). If create_test_user=True, creates a synthetic user
    and includes 'authenticated' — this creates an account on the target, so it's gated."""
    _require(target, "url", "api_key")
    sc = SupabaseApiScanner(target["url"], target["api_key"])
    identities = [("anon", {})]
    note = None
    if create_test_user:
        token = _signup_token(target)
        if token:
            identities.append(("authenticated", {"Authorization": f"Bearer {token}"}))
        else:
            note = "couldn't create a synthetic user (signup closed?); only 'anon' tested"

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
