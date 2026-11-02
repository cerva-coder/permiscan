"""Automatic recon: given a URL, identifies the stack, discovers exposed endpoints and
credentials, and routes to the existing adapters.

Everything starts from the target the user names (`recon <url>`); we only make
non-destructive GET requests, and the Supabase scan inherits the same opt-in flags as
`scan-api`.

Parsing functions are pure (text → signals) and testable without a network; HTTP access
is isolated in `Recon._get`, overridable in tests.
"""

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from permiscan.adapters.base import AdapterError
from permiscan.adapters.supabase_api import (
    ApiScanOptions,
    DetectedInstance,
    SupabaseApiScanner,
    detect_instances,
)
from permiscan.findings import Category, Confidence, Finding, Remediation, Severity

_TIMEOUT = 15
_MAX_BYTES = 3_000_000
_MAX_SCRIPTS = 10

# Common routes probed with GET; the sensitive ones become a finding if exposed.
COMMON_ROUTES = (
    "/rest/v1/", "/auth/v1/health", "/graphql", "/api",
    "/openapi.json", "/swagger.json", "/.env", "/.git/config", "/robots.txt",
)
_SENSITIVE_ROUTES = {"/.env", "/.git/config"}

_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")


@dataclass
class StackSignal:
    name: str
    confidence: str  # high | medium | low
    evidence: list[str] = field(default_factory=list)


@dataclass
class Endpoint:
    path: str
    status: int
    content_type: str = ""
    is_html: bool = False


@dataclass
class ReconResult:
    target: str
    stacks: list[StackSignal] = field(default_factory=list)
    firebase_config: dict = field(default_factory=dict)
    supabase_instances: list[DetectedInstance] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


# --- Stack detection (pure) --------------------------------------------------


def extract_firebase_config(text: str) -> dict:
    """Pulls firebaseConfig fields from a JS object (apiKey:"x") or JSON ("apiKey":"x")."""
    out = {}
    for key in ("apiKey", "authDomain", "projectId", "databaseURL", "storageBucket",
                "appId", "messagingSenderId"):
        m = re.search(rf'["\']?{key}["\']?\s*:\s*["\']([^"\']+)["\']', text)
        if m:
            out[key] = m.group(1)
    return out


def _looks_html(body: str) -> bool:
    head = body[:300].lstrip().lower()
    return head.startswith(("<!doctype html", "<html")) or "<head" in head or "<body" in head


def _body_sig(body: str) -> tuple[int, str]:
    import hashlib
    return len(body), hashlib.sha256(body[:20000].encode("utf-8", "replace")).hexdigest()[:16]


# Common collections tried during automatic Firestore enumeration.
COMMON_COLLECTIONS = (
    "users", "players", "profiles", "accounts", "scores", "scoreboard", "leaderboard",
    "rankings", "ranking", "games", "matches", "items", "inventory", "config", "settings",
    "messages", "chats", "posts", "orders", "payments", "transactions", "admin", "logs", "feedback",
)


def detect_stacks(text: str, headers: dict | None = None) -> list[StackSignal]:
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    hdr = " ".join(f"{k}: {v}" for k, v in headers.items())
    signals: list[StackSignal] = []

    def sig(name, confidence, *evidence):
        signals.append(StackSignal(name, confidence, [e for e in evidence if e]))

    # Firebase
    fb_ev = [p for p in ("firebaseapp.com", "firebaseio.com", "firebasedatabase.app",
                         "gstatic.com/firebasejs", "firebasestorage") if p in text]
    if extract_firebase_config(text).get("projectId"):
        sig("firebase", "high", "firebaseConfig in the code", *fb_ev)
    elif fb_ev:
        sig("firebase", "medium", *fb_ev)

    # Supabase
    sb_instances = detect_instances(text)
    if sb_instances:
        sig("supabase", "high", "project URL + key in the code")
    elif any(p in text for p in ("supabase.co", "supabase-js", "createClient(")):
        sig("supabase", "medium", "Supabase SDK/URL in the code")

    # Next.js
    nx = [p for p in ("__NEXT_DATA__", "/_next/static") if p in text]
    if nx or "next.js" in hdr or "x-nextjs" in hdr:
        sig("nextjs", "high" if nx else "medium", *nx, headers.get("x-powered-by"))

    # AWS
    aws_ev = [p for p in ("amazonaws.com", "cognito-idp", "AWSAccessKeyId") if p in text]
    aws_hdr = [k for k in headers if k.startswith("x-amz")]
    if aws_ev or aws_hdr:
        sig("aws", "high" if _AWS_ACCESS_KEY.search(text) else "medium", *aws_ev, *aws_hdr)

    # GCP
    gcp_ev = [p for p in ("googleapis.com", "appspot.com", "storage.googleapis.com") if p in text]
    if gcp_ev or "x-guploader-uploadid" in headers or "x-goog-" in hdr:
        sig("gcp", "medium", *gcp_ev)

    server = headers.get("server")
    if server and not any(s.name in ("nextjs",) for s in signals):
        sig(f"server:{server.split('/')[0].lower()}", "low", f"Server: {server}")

    return signals


# --- Endpoint discovery (pure) -----------------------------------------------


def extract_paths(html: str, base_url: str) -> list[str]:
    """Same-origin paths referenced in the HTML/JS."""
    base = urllib.parse.urlsplit(base_url)
    found = set()
    for m in re.finditer(r"""["'(]\s*(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,200})""", html):
        path = m.group(1)
        if not path.startswith("//") and "." not in path.rsplit("/", 1)[-1][:1]:  # skip //cdn and trivial paths
            found.add(path.split("?")[0])
    for m in re.finditer(r"""https?://[^\s"'<>)]+""", html):
        u = urllib.parse.urlsplit(m.group(0))
        if u.netloc == base.netloc and u.path and u.path != "/":
            found.add(u.path.split("?")[0])
    return sorted(p for p in found if len(p) > 1)[:50]


def script_srcs(html: str, base_url: str) -> list[str]:
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    base = urllib.parse.urlsplit(base_url)
    out = []
    for s in srcs:
        full = urllib.parse.urljoin(base_url, s)
        u = urllib.parse.urlsplit(full)
        if u.scheme in ("http", "https") and (u.netloc == base.netloc or "supabase" in u.netloc or "firebase" in u.netloc):
            out.append(full)
    return out[:_MAX_SCRIPTS]


# --- Orchestration (HTTP isolated in _get) -----------------------------------


# Scan level: controls how deep and aggressive the recon goes.
SCAN_LEVELS = {1: "minimal (identify)", 2: "medium (enumerate/read)", 3: "maximum (extract/active)"}


def options_for_level(level: int) -> ApiScanOptions:
    return {
        1: ApiScanOptions(rows=1),
        2: ApiScanOptions(rows=5, probe_rpc=True),
        3: ApiScanOptions(rows=25, probe_writes=True, probe_rpc=True, include_destructive=True),
    }[level]


class Recon:
    def __init__(self, url: str, options: ApiScanOptions | None = None, level: int = 2):
        if not url.startswith(("http://", "https://")):
            raise AdapterError("the URL must start with http:// or https://")
        self.url = url.rstrip("/")
        self.level = level
        self.options = options or options_for_level(level)

    def _get(self, url: str) -> tuple[int, dict, str]:
        return self._http(urllib.request.Request(url, headers={"User-Agent": "permiscan-recon"}))

    def _post(self, url: str, data: bytes) -> tuple[int, dict, str]:
        return self._http(urllib.request.Request(
            url, data=data, method="POST",
            headers={"User-Agent": "permiscan-recon", "Content-Type": "application/json"}))

    def _http(self, req) -> tuple[int, dict, str]:
        def norm(headers):  # lowercase keys: some servers send 'content-type' lowercased
            return {k.lower(): v for k, v in dict(headers).items()}
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 (scheme validated above)
                return resp.status, norm(resp.headers), resp.read(_MAX_BYTES).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, norm(e.headers), e.read(_MAX_BYTES).decode("utf-8", errors="replace")
        except urllib.error.URLError as e:
            raise AdapterError(f"failed to fetch {req.full_url}: {e.reason}") from None

    def _scan_supabase(self, inst: DetectedInstance) -> list[Finding]:
        return SupabaseApiScanner(inst.url, inst.anon_key, self.options).scan()

    def run(self) -> ReconResult:
        status, headers, html = self._get(self.url)
        result = ReconResult(self.url)

        # Aggregate the HTML and the same-origin JS bundles (where keys usually live).
        text = html
        for src in script_srcs(html, self.url):
            try:
                text += "\n" + self._get(src)[2]
            except AdapterError:
                continue
            if len(text) > _MAX_BYTES * 4:
                break

        result.stacks = detect_stacks(text, headers)
        page_cfg = extract_firebase_config(text)
        # If the config didn't come from the page/bundle, look in Firebase runtime files.
        if not page_cfg.get("projectId"):
            page_cfg = {**self._discover_firebase_config(), **page_cfg}
        result.firebase_config = page_cfg
        result.supabase_instances = detect_instances(text)
        result.endpoints = self._discover_endpoints(html)
        result.findings = self._route(result, text)
        result.recommendations = self._recommend(result)
        result.findings.sort(key=lambda f: (f.severity.rank, f.rule_id, f.resource))
        return result

    def _discover_endpoints(self, html: str) -> list[Endpoint]:
        # Baseline: a random route. In an SPA, every path returns the SAME index.html;
        # we compare the body (not status/headers) to avoid a false positive.
        try:
            _, _, base_body = self._get(f"{self.url}/permiscan-probe-404-xyz")
        except AdapterError:
            base_body = "\x00no-baseline"
        base_sig = _body_sig(base_body)
        endpoints = []
        for route in COMMON_ROUTES:
            try:
                st, hd, body = self._get(f"{self.url}{route}")
            except AdapterError:
                continue
            if _body_sig(body) == base_sig:  # SPA catch-all: same body as the baseline
                continue
            ctype = hd.get("content-type", "").split(";")[0]
            endpoints.append(Endpoint(route, st, ctype, is_html=_looks_html(body)))
        return endpoints

    # --- Automatic Firebase enumeration --------------------------------------

    def _discover_firebase_config(self) -> dict:
        for path in ("/__/firebase/init.json", "/config.json", "/firebase-config.json",
                     "/env.js", "/config.js", "/assets/config.js"):
            try:
                st, _, body = self._get(f"{self.url}{path}")
            except AdapterError:
                continue
            if st == 200 and not _looks_html(body):
                cfg = extract_firebase_config(body)
                if cfg.get("projectId"):
                    return cfg
        return {}

    def _enumerate_firebase(self, cfg: dict) -> list[Finding]:
        findings: list[Finding] = []
        pid, key = cfg.get("projectId"), cfg.get("apiKey")

        db = cfg.get("databaseURL")
        if db:
            findings += self._probe_rtdb(db)
        elif pid:  # try the default RTDB URL derived from the project
            findings += self._probe_rtdb(f"https://{pid}-default-rtdb.firebaseio.com")

        # Firestore: collection enumeration only from level 2 up.
        if self.level >= 2 and pid and key:
            findings += self._probe_firestore(pid, key)

        bucket = cfg.get("storageBucket") or (f"{pid}.appspot.com" if pid else None)
        if bucket:
            findings += self._probe_storage(bucket)

        # Open signup: level 3 only (creates a user on the target).
        if self.level >= 3 and key:
            findings += self._probe_auth_signup(key)
        return findings

    def _probe_firestore(self, project_id: str, api_key: str) -> list[Finding]:
        page = 5 if self.level >= 3 else 1  # level 3 extracts more documents
        found: dict[str, list[str]] = {}
        for col in COMMON_COLLECTIONS:
            url = (f"https://firestore.googleapis.com/v1/projects/{project_id}"
                   f"/databases/(default)/documents/{col}?pageSize={page}&key={api_key}")
            try:
                st, _, body = self._get(url)
            except AdapterError:
                continue
            if st == 200 and '"documents"' in body:
                docs = re.findall(r'"name":\s*"projects/[^"]*?/documents/([^"]+)"', body)
                found[col] = docs[:page]
        return [_firestore_finding(project_id, found, self.level)] if found else []

    def _probe_storage(self, bucket: str) -> list[Finding]:
        limit = 100 if self.level >= 3 else 10
        url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?maxResults={limit}"
        try:
            st, _, body = self._get(url)
        except AdapterError:
            return []
        if st != 200 or ('"items"' not in body and '"prefixes"' not in body):
            return []
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {}
        names = [it.get("name", "") for it in data.get("items", [])][:50]
        return [_storage_finding(bucket, url, names, self.level)]

    def _probe_auth_signup(self, api_key: str) -> list[Finding]:
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
        try:
            st, _, body = self._post(url, b'{"returnSecureToken":true}')
        except AdapterError:
            return []
        if st == 200 and '"idToken"' in body:
            return [_auth_signup_finding(url)]
        return []

    def _route(self, result: ReconResult, text: str) -> list[Finding]:
        findings: list[Finding] = []

        for inst in result.supabase_instances:
            if inst.anon_key:
                try:
                    findings += self._scan_supabase(inst)
                except AdapterError as e:
                    # If the Supabase URL is invalid or the key doesn't work, don't fail outright
                    if "getaddrinfo failed" in str(e) or "name resolution" in str(e).lower():
                        findings.append(Finding(
                            rule_id="supabase-invalid-url",
                            title="Invalid Supabase URL detected in the code",
                            description=f"The URL {inst.url} was detected in the code but doesn't resolve in DNS. This suggests a stale or incorrect Supabase URL left in the source.",
                            category=Category.STORAGE, provider="supabase-api", resource=inst.url,
                            severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                            remediation=Remediation(summary="Remove the stale URL from the source, or update it to the correct Supabase project URL.")
                        ))
                    elif "401" in str(e):
                        # Key rejected - probably doesn't match the URL
                        key_info = f" (ref={inst.keys[0].get('ref')})" if inst.keys and inst.keys[0].get('ref') else ""
                        findings.append(Finding(
                            rule_id="supabase-key-url-mismatch",
                            title="Supabase key doesn't match the detected URL",
                            description=f"The detected key{key_info} was rejected by {inst.url}. This may mean the key belongs to a different project than the URL, or that it expired/was revoked. To scan with the correct credentials, use: permiscan scan-api --url <CORRECT_URL> --key <CORRECT_KEY>",
                            category=Category.AUTHENTICATION, provider="supabase-api", resource=inst.url,
                            severity=Severity.LOW, confidence=Confidence.POSSIBLE,
                            remediation=Remediation(summary="Check that the key and the URL belong to the same Supabase project. Get the correct key from Supabase Dashboard > Settings > API > anon/public key.")
                        ))
                    else:
                        findings.append(Finding(
                            rule_id="supabase-scan-error",
                            title="Error scanning a Supabase instance",
                            description=f"Attempt to scan {inst.url} failed: {str(e)}",
                            category=Category.AUTHORIZATION, provider="supabase-api", resource=inst.url,
                            severity=Severity.INFO, confidence=Confidence.POSSIBLE,
                            remediation=Remediation(summary="Check that the URL and key are correct.")
                        ))

        if result.firebase_config.get("projectId") or result.firebase_config.get("databaseURL"):
            findings += self._enumerate_firebase(result.firebase_config)

        for key in sorted(set(_AWS_ACCESS_KEY.findall(text))):
            findings.append(_aws_key_finding(key))

        for ep in result.endpoints:
            # Exposed sensitive file: only when the body differs from the catch-all (already
            # filtered in _discover_endpoints) AND it's not HTML (a fallback index.html
            # isn't a real .env).
            if ep.path in _SENSITIVE_ROUTES and ep.status == 200 and not ep.is_html:
                findings.append(_exposed_file_finding(self.url, ep))

        return findings

    def _probe_rtdb(self, db_url: str) -> list[Finding]:
        try:
            status, headers, body = self._get(f"{db_url.rstrip('/')}/.json?shallow=true")
        except AdapterError:
            return []
        # RTDB returns JSON; a 200 with HTML is an error/SPA page, not exposed data.
        if status == 200 and not _looks_html(body) and body.strip() not in ("", "null"):
            keys = re.findall(r'"([^"]+)"\s*:', body)[:20]
            return [Finding(
                rule_id="firebase-rtdb-public-read",
                title="Realtime Database readable without authentication",
                description=(
                    f"{db_url} responded to an anonymous read (/.json): the \".read\" rule allows access "
                    "without authentication and the entire database is exposed."
                ),
                category=Category.AUTHORIZATION, provider="firebase", resource=db_url,
                severity=Severity.HIGH, confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API1:2023",
                evidence={"observed_as": "anon", "top_level_keys": keys},
                poc=f"curl '{db_url.rstrip('/')}/.json?shallow=true'",
                remediation=Remediation(
                    summary='Require authentication on ".read"/".write" and tie access to the owner (auth.uid).',
                    references=["https://firebase.google.com/docs/database/security"]),
            )]
        return []

    def _recommend(self, result: ReconResult) -> list[str]:
        rec = []
        if result.firebase_config.get("projectId") and not result.findings:
            rec.append(
                "Firebase detected: Security Rules can't be downloaded remotely. Fetch them "
                "(firebase deploy/console) and run `permiscan scan-rules --rules firestore.rules`."
            )
        if any(s.name == "supabase" for s in result.stacks) and not result.supabase_instances:
            rec.append("Supabase detected, but couldn't find the anon key on the page; provide it via `scan-api --url …`.")
        if not result.findings:
            rec.append("No exposure confirmed from the public surface. For the database, use `scan`/`scan-api` with credentials.")
        return rec


def _aws_key_finding(key: str) -> Finding:
    return Finding(
        rule_id="exposed-aws-access-key",
        title="AWS Access Key ID exposed on the client",
        description=f"An AWS Access Key ID ({key[:8]}…) appears in the code shipped to the browser. "
        "AWS keys should never be embedded in a frontend.",
        category=Category.AUTHENTICATION, provider="aws", resource=f"aws:{key[:8]}",
        severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED, cwe="CWE-798", owasp="API2:2023",
        evidence={"key_id_prefix": key[:8]},
        remediation=Remediation(summary="Rotate the key immediately and move the credentials to the server.",
                                references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"]),
    )


_FB_DB_DOCS = "https://firebase.google.com/docs/firestore/security/get-started"
_FB_STORAGE_DOCS = "https://firebase.google.com/docs/storage/security"


def _firestore_finding(project_id: str, found: dict[str, list[str]], level: int) -> Finding:
    cols = list(found)
    sample = {c: docs for c, docs in found.items() if docs}
    desc = (
        f"Collections [{', '.join(cols)}] of project {project_id} returned documents for an "
        "anonymous read over REST: the Security Rules allow public reads."
    )
    if level >= 3 and sample:
        first = next(iter(sample))
        desc += f" Sample pulled from '{first}': {', '.join(sample[first][:3])}."
    return Finding(
        rule_id="firebase-firestore-public-read",
        title="Firestore collections readable without authentication",
        description=desc,
        category=Category.AUTHORIZATION, provider="firebase", resource=f"firestore:{project_id}",
        severity=Severity.HIGH, confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API1:2023",
        evidence={"observed_as": "anon", "collections": cols, "sample_documents": sample},
        poc=f"curl 'https://firestore.googleapis.com/v1/projects/{project_id}"
        f"/databases/(default)/documents/{cols[0]}?key=$FIREBASE_API_KEY'",
        remediation=Remediation(
            summary="Require authentication and ownership in the rules "
            "(e.g. 'allow read: if request.auth != null && request.auth.uid == resource.data.ownerId').",
            references=[_FB_DB_DOCS]),
    )


def _storage_finding(bucket: str, url: str, names: list[str], level: int) -> Finding:
    desc = (
        f"Bucket {bucket} responded to an anonymous object listing: the Storage rules allow "
        "access without authentication, exposing the stored files."
    )
    if names:
        desc += f" {len(names)} file(s) visible, e.g.: {', '.join(names[:5])}."
    evidence = {"observed_as": "anon", "bucket": bucket, "files": names}
    if level >= 3 and names:  # extraction: direct download URLs
        evidence["download_urls"] = [
            f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{urllib.parse.quote(n, safe='')}?alt=media"
            for n in names[:20]
        ]
    return Finding(
        rule_id="firebase-storage-public-list",
        title="Firebase Storage with public listing",
        description=desc,
        category=Category.STORAGE, provider="firebase", resource=f"storage:{bucket}",
        severity=Severity.HIGH, confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API1:2023",
        evidence=evidence,
        poc=f"curl '{url}'",
        remediation=Remediation(
            summary="Require authentication in the Storage rules and tie access to the file's owner.",
            references=[_FB_STORAGE_DOCS]),
    )


def _auth_signup_finding(url: str) -> Finding:
    return Finding(
        rule_id="firebase-auth-signup-open",
        title="Open user signup (Firebase Auth)",
        description=(
            "The Identity Toolkit signup endpoint created a user with no restriction: anyone can "
            "sign up and get an idToken. Combined with rules that trust request.auth != null, "
            "this grants access to data meant to be 'authenticated only'."
        ),
        category=Category.AUTHENTICATION, provider="firebase", resource="firebase-auth:signUp",
        severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API2:2023",
        evidence={"probe": "accounts:signUp", "observed_as": "anon"},
        poc=f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{{\"returnSecureToken\":true}}'",
        remediation=Remediation(
            summary="If open signup isn't intended, disable the public providers in Firebase Auth "
            "and don't base authorization solely on 'authenticated user'.",
            references=["https://firebase.google.com/docs/auth"]),
    )


def _exposed_file_finding(base_url: str, ep: Endpoint) -> Finding:
    return Finding(
        rule_id="exposed-sensitive-file",
        title=f"Sensitive file publicly accessible ({ep.path})",
        description=f"{ep.path} responded with HTTP 200 and non-HTML content: the file may be exposed "
        "to the public, leaking secrets or repository history.",
        category=Category.STORAGE, provider="http", resource=ep.path,
        severity=Severity.CRITICAL, confidence=Confidence.LIKELY, cwe="CWE-538", owasp="API8:2023",
        evidence={"status": ep.status, "content_type": ep.content_type},
        poc=f"curl -i '{base_url}{ep.path}'",
        remediation=Remediation(summary="Block access to the file on the server/CDN and remove any versioned secrets."),
    )
