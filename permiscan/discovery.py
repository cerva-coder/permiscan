"""Reconhecimento automático: dada uma URL, identifica a stack, descobre endpoints e
credenciais expostas e roteia para os adaptadores existentes.

Tudo parte do alvo que o usuário nomeia (`recon <url>`); fazemos apenas requisições GET
não destrutivas, e a varredura do Supabase herda as mesmas flags opt-in do `scan-api`.

As funções de parsing são puras (texto → sinais) e testáveis sem rede; o acesso HTTP fica
isolado em `Recon._get`, sobrescrevível nos testes.
"""

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

# Rotas comuns sondadas com GET; as sensíveis viram finding se expostas.
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


# --- Detecção de stack (puro) ----------------------------------------------


def extract_firebase_config(text: str) -> dict:
    """Puxa os campos do firebaseConfig de objeto JS (apiKey:"x") ou JSON ("apiKey":"x")."""
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


# Coleções comuns tentadas na enumeração automática do Firestore.
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
        sig("firebase", "high", "firebaseConfig no código", *fb_ev)
    elif fb_ev:
        sig("firebase", "medium", *fb_ev)

    # Supabase
    sb_instances = detect_instances(text)
    if sb_instances:
        sig("supabase", "high", "URL do projeto + chave no código")
    elif any(p in text for p in ("supabase.co", "supabase-js", "createClient(")):
        sig("supabase", "medium", "SDK/URL do Supabase no código")

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


# --- Descoberta de endpoints (puro) ----------------------------------------


def extract_paths(html: str, base_url: str) -> list[str]:
    """Caminhos same-origin referenciados no HTML/JS."""
    base = urllib.parse.urlsplit(base_url)
    found = set()
    for m in re.finditer(r"""["'(]\s*(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,200})""", html):
        path = m.group(1)
        if not path.startswith("//") and "." not in path.rsplit("/", 1)[-1][:1]:  # ignora //cdn e caminhos triviais
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


# --- Orquestração (HTTP isolado em _get) ------------------------------------


class Recon:
    def __init__(self, url: str, options: ApiScanOptions | None = None):
        if not url.startswith(("http://", "https://")):
            raise AdapterError("a URL deve começar com http:// ou https://")
        self.url = url.rstrip("/")
        self.options = options or ApiScanOptions()

    def _get(self, url: str) -> tuple[int, dict, str]:
        return self._http(urllib.request.Request(url, headers={"User-Agent": "permiscan-recon"}))

    def _post(self, url: str, data: bytes) -> tuple[int, dict, str]:
        return self._http(urllib.request.Request(
            url, data=data, method="POST",
            headers={"User-Agent": "permiscan-recon", "Content-Type": "application/json"}))

    def _http(self, req) -> tuple[int, dict, str]:
        def norm(headers):  # chaves minúsculas: alguns servidores mandam 'content-type' minúsculo
            return {k.lower(): v for k, v in dict(headers).items()}
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 (esquema validado)
                return resp.status, norm(resp.headers), resp.read(_MAX_BYTES).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, norm(e.headers), e.read(_MAX_BYTES).decode("utf-8", errors="replace")
        except urllib.error.URLError as e:
            raise AdapterError(f"falha ao buscar {req.full_url}: {e.reason}") from None

    def _scan_supabase(self, inst: DetectedInstance) -> list[Finding]:
        return SupabaseApiScanner(inst.url, inst.anon_key, self.options).scan()

    def run(self) -> ReconResult:
        status, headers, html = self._get(self.url)
        result = ReconResult(self.url)

        # Agrega o HTML e os bundles JS same-origin (onde as chaves costumam estar).
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
        # Se a config não veio da página/bundle, procura em arquivos de runtime do Firebase.
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
        # Baseline: rota aleatória. Numa SPA, todo caminho devolve o MESMO index.html;
        # comparamos o corpo (não o status/header) para não dar falso positivo.
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
            if _body_sig(body) == base_sig:  # catch-all da SPA: mesmo corpo da baseline
                continue
            ctype = hd.get("content-type", "").split(";")[0]
            endpoints.append(Endpoint(route, st, ctype, is_html=_looks_html(body)))
        return endpoints

    # --- Enumeração automática do Firebase ----------------------------------

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
        elif pid:  # tenta a URL padrão de RTDB derivada do projeto
            findings += self._probe_rtdb(f"https://{pid}-default-rtdb.firebaseio.com")

        if pid and key:
            findings += self._probe_firestore(pid, key)

        bucket = cfg.get("storageBucket") or (f"{pid}.appspot.com" if pid else None)
        if bucket:
            findings += self._probe_storage(bucket)

        if self.options.probe_writes and key:
            findings += self._probe_auth_signup(key)
        return findings

    def _probe_firestore(self, project_id: str, api_key: str) -> list[Finding]:
        accessible = []
        for col in COMMON_COLLECTIONS:
            url = (f"https://firestore.googleapis.com/v1/projects/{project_id}"
                   f"/databases/(default)/documents/{col}?pageSize=1&key={api_key}")
            try:
                st, _, body = self._get(url)
            except AdapterError:
                continue
            if st == 200 and '"documents"' in body:
                accessible.append(col)
        return [_firestore_finding(project_id, accessible)] if accessible else []

    def _probe_storage(self, bucket: str) -> list[Finding]:
        url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?maxResults=10"
        try:
            st, _, body = self._get(url)
        except AdapterError:
            return []
        if st == 200 and ('"items"' in body or '"prefixes"' in body):
            return [_storage_finding(bucket, url)]
        return []

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
                    # Se a URL do Supabase for inválida ou a chave não funcionar, não falhar totalmente
                    if "getaddrinfo failed" in str(e) or "name resolution" in str(e).lower():
                        findings.append(Finding(
                            rule_id="supabase-invalid-url",
                            title=f"URL Supabase inválida detectada no código",
                            description=f"A URL {inst.url} foi detectada no código mas não existe no DNS. Isso indica uma URL de Supabase antiga ou incorreta que foi deixada no código fonte.",
                            category=Category.STORAGE, provider="supabase-api", resource=inst.url,
                            severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                            remediation=Remediation(summary="Remova a URL antiga do código fonte ou atualize para a URL correta do projeto Supabase.")
                        ))
                    elif "401" in str(e):
                        # Chave rejeitada - provavelmente a chave não corresponde à URL
                        key_info = f" (ref={inst.keys[0].get('ref')})" if inst.keys and inst.keys[0].get('ref') else ""
                        findings.append(Finding(
                            rule_id="supabase-key-url-mismatch",
                            title=f"Chave Supabase não corresponde à URL detectada",
                            description=f"A chave detectada{key_info} foi rejeitada pela URL {inst.url}. Isso pode indicar que a chave é de um projeto diferente da URL, ou que a chave expirou/foi revogada. Para escanear com credenciais corretas, use: permiscan scan-api --url <CORRECT_URL> --key <CORRECT_KEY>",
                            category=Category.AUTHENTICATION, provider="supabase-api", resource=inst.url,
                            severity=Severity.LOW, confidence=Confidence.POSSIBLE,
                            remediation=Remediation(summary="Verifique se a chave e a URL correspondem ao mesmo projeto Supabase. Obtenha a chave correta via Supabase Dashboard > Settings > API > anon/public key.")
                        ))
                    else:
                        findings.append(Finding(
                            rule_id="supabase-scan-error",
                            title=f"Erro ao escanear instância Supabase",
                            description=f"Tentativa de escanear {inst.url} falhou: {str(e)}",
                            category=Category.AUTHORIZATION, provider="supabase-api", resource=inst.url,
                            severity=Severity.INFO, confidence=Confidence.POSSIBLE,
                            remediation=Remediation(summary="Verifique se a URL e a chave estão corretas.")
                        ))

        if result.firebase_config.get("projectId") or result.firebase_config.get("databaseURL"):
            findings += self._enumerate_firebase(result.firebase_config)

        for key in sorted(set(_AWS_ACCESS_KEY.findall(text))):
            findings.append(_aws_key_finding(key))

        for ep in result.endpoints:
            # Arquivo sensível exposto: só quando o corpo difere do catch-all (já filtrado em
            # _discover_endpoints) E não é HTML (um index.html de fallback não é um .env real).
            if ep.path in _SENSITIVE_ROUTES and ep.status == 200 and not ep.is_html:
                findings.append(_exposed_file_finding(self.url, ep))

        return findings

    def _probe_rtdb(self, db_url: str) -> list[Finding]:
        try:
            status, headers, body = self._get(f"{db_url.rstrip('/')}/.json?shallow=true")
        except AdapterError:
            return []
        # RTDB devolve JSON; um 200 com HTML é página de erro/SPA, não dado exposto.
        if status == 200 and not _looks_html(body) and body.strip() not in ("", "null"):
            keys = re.findall(r'"([^"]+)"\s*:', body)[:20]
            return [Finding(
                rule_id="firebase-rtdb-public-read",
                title="Realtime Database legível sem autenticação",
                description=(
                    f"{db_url} respondeu a uma leitura anônima (/.json): a regra \".read\" permite acesso "
                    "sem autenticação e todo o banco fica exposto."
                ),
                category=Category.AUTHORIZATION, provider="firebase", resource=db_url,
                severity=Severity.HIGH, confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API1:2023",
                evidence={"observed_as": "anon", "top_level_keys": keys},
                poc=f"curl '{db_url.rstrip('/')}/.json?shallow=true'",
                remediation=Remediation(
                    summary='Exija autenticação em ".read"/".write" e vincule o acesso ao dono (auth.uid).',
                    references=["https://firebase.google.com/docs/database/security"]),
            )]
        return []

    def _recommend(self, result: ReconResult) -> list[str]:
        rec = []
        if result.firebase_config.get("projectId") and not result.findings:
            rec.append(
                "Firebase detectado: as Security Rules não são baixáveis remotamente. Baixe-as "
                "(firebase deploy/console) e rode `permiscan scan-rules --rules firestore.rules`."
            )
        if any(s.name == "supabase" for s in result.stacks) and not result.supabase_instances:
            rec.append("Supabase detectado, mas não achei a chave anon na página; forneça-a em `scan-api --url …`.")
        if not result.findings:
            rec.append("Nenhuma exposição confirmada pela superfície pública. Para o banco, use `scan`/`scan-api` com credenciais.")
        return rec


def _aws_key_finding(key: str) -> Finding:
    return Finding(
        rule_id="exposed-aws-access-key",
        title="AWS Access Key ID exposto no cliente",
        description=f"Uma AWS Access Key ID ({key[:8]}…) aparece no código entregue ao navegador. "
        "Chaves AWS nunca devem ser embarcadas no frontend.",
        category=Category.AUTHENTICATION, provider="aws", resource=f"aws:{key[:8]}",
        severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED, cwe="CWE-798", owasp="API2:2023",
        evidence={"key_id_prefix": key[:8]},
        remediation=Remediation(summary="Rotacione a chave imediatamente e mova as credenciais para o servidor.",
                                references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"]),
    )


_FB_DB_DOCS = "https://firebase.google.com/docs/firestore/security/get-started"
_FB_STORAGE_DOCS = "https://firebase.google.com/docs/storage/security"


def _firestore_finding(project_id: str, collections: list[str]) -> Finding:
    cols = ", ".join(collections)
    return Finding(
        rule_id="firebase-firestore-public-read",
        title="Coleções do Firestore legíveis sem autenticação",
        description=(
            f"As coleções [{cols}] do projeto {project_id} retornaram documentos para uma leitura "
            "anônima via REST: as Security Rules permitem leitura pública. Confirme se é intencional."
        ),
        category=Category.AUTHORIZATION, provider="firebase", resource=f"firestore:{project_id}",
        severity=Severity.HIGH, confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API1:2023",
        evidence={"observed_as": "anon", "collections": collections},
        poc=f"curl 'https://firestore.googleapis.com/v1/projects/{project_id}"
        f"/databases/(default)/documents/{collections[0]}?key=$FIREBASE_API_KEY'",
        remediation=Remediation(
            summary="Exija autenticação e propriedade nas rules "
            "(ex.: 'allow read: if request.auth != null && request.auth.uid == resource.data.ownerId').",
            references=[_FB_DB_DOCS]),
    )


def _storage_finding(bucket: str, url: str) -> Finding:
    return Finding(
        rule_id="firebase-storage-public-list",
        title="Firebase Storage com listagem pública",
        description=(
            f"O bucket {bucket} respondeu à listagem anônima de objetos: as rules de Storage permitem "
            "acesso sem autenticação, expondo os arquivos armazenados."
        ),
        category=Category.STORAGE, provider="firebase", resource=f"storage:{bucket}",
        severity=Severity.HIGH, confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API1:2023",
        evidence={"observed_as": "anon", "bucket": bucket},
        poc=f"curl '{url}'",
        remediation=Remediation(
            summary="Exija autenticação nas rules de Storage e vincule o acesso ao dono do arquivo.",
            references=[_FB_STORAGE_DOCS]),
    )


def _auth_signup_finding(url: str) -> Finding:
    return Finding(
        rule_id="firebase-auth-signup-open",
        title="Cadastro de usuários aberto (Firebase Auth)",
        description=(
            "O endpoint de signup do Identity Toolkit criou um usuário sem restrição: qualquer um pode "
            "se cadastrar e obter um idToken. Combinado com rules que confiam em request.auth != null, "
            "isso dá acesso a dados 'só para autenticados'."
        ),
        category=Category.AUTHENTICATION, provider="firebase", resource="firebase-auth:signUp",
        severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, cwe="CWE-284", owasp="API2:2023",
        evidence={"probe": "accounts:signUp", "observed_as": "anon"},
        poc=f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{{\"returnSecureToken\":true}}'",
        remediation=Remediation(
            summary="Se o cadastro aberto não for desejado, desative os provedores públicos no Firebase Auth "
            "e não baseie autorização apenas em 'usuário autenticado'.",
            references=["https://firebase.google.com/docs/auth"]),
    )


def _exposed_file_finding(base_url: str, ep: Endpoint) -> Finding:
    return Finding(
        rule_id="exposed-sensitive-file",
        title=f"Arquivo sensível acessível publicamente ({ep.path})",
        description=f"{ep.path} respondeu com HTTP 200 e conteúdo não-HTML: o arquivo pode estar exposto "
        "ao público, vazando segredos ou histórico do repositório.",
        category=Category.STORAGE, provider="http", resource=ep.path,
        severity=Severity.CRITICAL, confidence=Confidence.LIKELY, cwe="CWE-538", owasp="API8:2023",
        evidence={"status": ep.status, "content_type": ep.content_type},
        poc=f"curl -i '{base_url}{ep.path}'",
        remediation=Remediation(summary="Bloqueie o acesso ao arquivo no servidor/CDN e remova segredos versionados."),
    )
