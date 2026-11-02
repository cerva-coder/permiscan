"""External (black-box) scan of a Supabase project through the Data API.

Uses only the project URL and the anon key — both public by design, embedded in any
frontend. We observe what an anonymous request can actually do, which is exactly the
surface an unauthenticated client reaches.

Proof modes (all optional, each with its own CLI flag):
- read (default): reads a sample of rows as anonymous;
- write (`--probe-writes`): tries a `POST` to see if anon can insert;
- RPC (`--probe-rpc`): calls RPC functions to see if they respond without authentication.

Write and RPC probes alter the target; only use them where you're authorized. Functions
with a destructive-sounding name (delete/drop/admin/…) aren't called without `--include-destructive`.
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

# ---- Credential detection (what the extension's content script does) -------

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_SB_CLOUD_URL = re.compile(r"https://[a-z0-9-]+\.supabase\.co", re.I)
_SB_URL_ASSIGN = re.compile(r"""supabase[_-]?url["'\s:=]+(https://[^\s"'`,}\\]+)""", re.I)
# New (non-JWT) Supabase keys: sb_publishable_… and sb_secret_…
_SB_KEY = re.compile(r"sb_(?:publishable|secret)_[A-Za-z0-9_-]{8,}")

# ---- RPC risk classification by name ---------------------------------------

# Tokens in snake_case names; no trailing \b because '_' counts as a word character.
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
    return {"key": key, "role": claims.get("role", "unknown"), "ref": claims.get("ref")}


def detect_instances(text: str) -> list[DetectedInstance]:
    """Extracts project URLs and keys from a text (HTML, JS bundle, .env…),
    pairing them by project ref when the JWT states one."""
    urls = {u.rstrip("/").lower() for u in _SB_CLOUD_URL.findall(text)}
    urls |= {m.rstrip("/").lower() for m in _SB_URL_ASSIGN.findall(text)}

    # Filter out obvious dead-code/placeholder URLs
    invalid_refs = {"undefined", "null", "your-project", "example", "placeholder", "test"}
    urls = {u for u in urls if not any(ref in u for ref in invalid_refs)}

    keys = []
    for token in set(_JWT.findall(text)):
        claims = jwt_claims(token)
        # Looser match: accept JWTs with a typical Supabase shape even without an explicit iss
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
    # Keys with no matching ref: pair with the only URL, if there's just one
    if unpaired and len(instances) == 1:
        next(iter(instances.values())).keys.extend(unpaired)
    # Multiple URLs and ref-less keys: don't distribute (avoids false positives).
    # Only distribute sb_* keys (which carry no ref in a JWT).
    elif unpaired and len(instances) > 1:
        sb_keys = [k for k in unpaired if k["key"].startswith("sb_")]
        for k in sb_keys:
            for inst in instances.values():
                inst.keys.append(k)
    return list(instances.values())


def fetch_text(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        raise AdapterError("the URL must start with http:// or https://")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 (scheme validated above)
            return resp.read(5_000_000).decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        raise AdapterError(f"failed to fetch {url}: {getattr(e, 'reason', e)}") from None


# ---- Scanner ----------------------------------------------------------------


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
            raise AdapterError("the project URL must start with http:// or https://")
        self.base_url = base_url.rstrip("/")
        self.key = anon_key
        self.options = options or ApiScanOptions()
        self.rest = f"{self.base_url}/rest/v1"

    # --- HTTP -----------------------------------------------------------

    def _request(self, path, *, method="GET", headers=None, data=None):
        req = urllib.request.Request(
            f"{self.rest}{path}", method=method, data=data,
            headers={"apikey": self.key, "Authorization": f"Bearer {self.key}", "Accept": "application/json",
                     **(headers or {})},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 (scheme validated in __init__)
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()
        except urllib.error.URLError as e:
            raise AdapterError(f"failed to connect to {self.base_url}: {e.reason}") from None

    def _openapi(self) -> dict:
        status, _, body = self._request("/")
        if status == 401:
            raise AdapterError("key rejected (HTTP 401): check the key and the project URL")
        if status != 200:
            raise AdapterError(f"OpenAPI unavailable at {self.rest}/ (HTTP {status})")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise AdapterError("the OpenAPI response isn't JSON; does the URL point to a Supabase project?") from None

    # --- Discovery / probes ----------------------------------------------

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
        """Reads up to `rows` rows as anonymous. None = anon can't read."""
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
            return None  # empty or RLS active: not a finding
        columns = tuple(data[0].keys()) if data else ()
        sample = [{k: _truncate(v) for k, v in row.items()} for row in data[:5]]
        return ApiTable(name, columns, count, sample)

    def _test_write(self, name: str) -> str:
        """'inserted' | 'allowed' (passed RLS, blocked by a constraint) | 'blocked' | 'unknown'."""
        status, _, body = self._request(
            f"/{name}", method="POST", data=b"{}",
            headers={"Content-Type": "application/json", "Prefer": "return=minimal"},
        )
        low = body.decode(errors="replace").lower()
        if status in (200, 201, 204):
            return "inserted"
        if status in (401, 403) or re.search(r"row-level security|policy|permission|not authoriz|jwt", low):
            return "blocked"
        if status in (400, 409):  # data/constraint error => RLS let it through
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
            return "accessible"  # exists and responded; just missing arguments
        return "unknown"

    # --- Interface ---------------------------------------------------------

    def check(self) -> dict[str, Any]:
        claims = jwt_claims(self.key)
        tables, rpcs = self._tables_and_rpcs(self._openapi())
        return {
            "provider": self.provider,
            "target": self.base_url,
            "project_ref": claims.get("ref") or _project_ref(self.base_url),
            "key_role": claims.get("role") or ("service_role" if self.key.startswith("sb_secret_") else "unknown"),
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

    # --- Finding builders ----------------------------------------------------

    def _service_role_finding(self, claims: dict) -> Finding:
        return Finding(
            rule_id="supabase-service-role-key",
            title="service_role key in use on the client",
            description=(
                "The provided key bypasses all RLS and grants full access to the Data API. If it came "
                "from a frontend or public code, it's a critical exposure; it must never leave the server."
            ),
            category=Category.AUTHENTICATION, provider=self.provider,
            resource=f"project:{claims.get('ref') or _project_ref(self.base_url) or self.base_url}",
            severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED, cwe="CWE-200", owasp="API2:2023",
            evidence={"role": "service_role", "ref": claims.get("ref")},
            poc=f"curl '{self.rest}/' -H 'apikey: $SERVICE_ROLE_KEY'  # full access, bypasses RLS",
            remediation=Remediation(
                summary="Revoke/rotate the key and use only the anon/publishable key on the client.",
                references=[_DOCS_KEYS]),
        )

    def _read_finding(self, table: ApiTable) -> Finding:
        severity, flagged = most_sensitive(list(table.columns))
        if severity == Severity.INFO:
            severity = Severity.MEDIUM
        return Finding(
            rule_id="supabase-api-anon-read",
            title="Table readable by an anonymous request",
            description=(
                f"Table '{table.name}' returned data for an anonymous request through the Data API: RLS "
                "is disabled, or there's a policy that grants the anon role access. Confirm whether public "
                "access is intentional; if not, this is unauthenticated data exposure."
                + (f" Sensitive columns by name: {', '.join(flagged)}." if flagged else "")
            ),
            category=Category.AUTHORIZATION, provider=self.provider, resource=f"rest/v1/{table.name}",
            severity=severity, confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API1:2023",
            evidence={"columns": list(table.columns), "row_count": table.row_count,
                      "sensitive_columns": flagged, "sample": table.sample, "observed_as": "anon"},
            poc=f"curl '{self.rest}/{table.name}?select=*&limit=3' -H 'apikey: $ANON_KEY'",
            remediation=Remediation(
                summary="Enable RLS and create policies that require authentication and ownership; if it "
                "shouldn't be public, revoke access for the anon role.",
                sql=f'ALTER TABLE "{table.name}" ENABLE ROW LEVEL SECURITY;', references=[_DOCS_RLS]),
        )

    def _write_finding(self, name: str, result: str) -> Finding:
        inserted = result == "inserted"
        return Finding(
            rule_id="supabase-api-anon-write",
            title="Table writable by an anonymous request",
            description=(
                f"An anonymous write request (POST) to '{name}' "
                + ("inserted a row: " if inserted else "passed RLS and was only blocked by a data constraint "
                   "(NOT NULL/constraint): ")
                + "the anon role can write without authentication."
            ),
            category=Category.AUTHORIZATION, provider=self.provider, resource=f"rest/v1/{name}",
            severity=Severity.CRITICAL if inserted else Severity.HIGH,
            confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API1:2023",
            evidence={"probe": "POST {}", "result": result, "observed_as": "anon"},
            poc=f"curl -X POST '{self.rest}/{name}' -H 'apikey: $ANON_KEY' "
            "-H 'Content-Type: application/json' -d '{}'",
            remediation=Remediation(
                summary="Enable RLS and create an INSERT policy that requires authentication and ownership; "
                "revoke INSERT/UPDATE/DELETE from the anon role if writes shouldn't be public.",
                references=[_DOCS_RLS]),
        )

    def _rpc_finding(self, name: str, risk: Severity) -> Finding:
        return Finding(
            rule_id="supabase-api-anon-rpc",
            title="RPC function callable by an anonymous request",
            description=(
                f"Function '{name}' responded to an anonymous call (POST /rpc/{name}) without requiring "
                "authentication. The risk depends on what the function does; its name suggests "
                f"{risk.value} severity. Confirm whether this exposure is intentional and whether the "
                "function validates identity."
            ),
            category=Category.AUTHORIZATION, provider=self.provider, resource=f"rest/v1/rpc/{name}",
            severity=risk if risk.rank < Severity.MEDIUM.rank else Severity.MEDIUM,
            confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API5:2023",
            evidence={"probe": "POST {}", "risk_by_name": risk.value, "observed_as": "anon"},
            poc=f"curl -X POST '{self.rest}/rpc/{name}' -H 'apikey: $ANON_KEY' "
            "-H 'Content-Type: application/json' -d '{}'",
            remediation=Remediation(
                summary="Restrict execution (REVOKE EXECUTE … FROM anon) or validate auth.uid() inside the "
                "function; only expose through the Data API the functions meant to be public.",
                references=[_DOCS_RLS]),
        )

    def _rpc_skipped_finding(self, name: str) -> Finding:
        return Finding(
            rule_id="supabase-api-rpc-exposed",
            title="RPC function with a destructive-sounding name exposed (not called)",
            description=(
                f"Function '{name}' is exposed on the Data API and its name suggests a destructive effect. "
                "It wasn't called automatically to avoid altering the target. Run with --include-destructive "
                "to test it, preferably on your own or a test project."
            ),
            category=Category.AUTHORIZATION, provider=self.provider, resource=f"rest/v1/rpc/{name}",
            severity=Severity.INFO, confidence=Confidence.POSSIBLE, cwe="CWE-284", owasp="API5:2023",
            evidence={"risk_by_name": "critical", "tested": False},
            remediation=Remediation(
                summary="Confirm whether this function should be callable through the public API; if not, revoke EXECUTE from anon.",
                references=[_DOCS_RLS]),
        )
