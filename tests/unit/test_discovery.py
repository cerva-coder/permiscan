import base64
import json

from permiscan.discovery import (
    Recon,
    detect_stacks,
    extract_firebase_config,
    extract_paths,
    script_srcs,
)


def make_jwt(claims: dict) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJIUzI1NiJ9.{payload}.sig"


ANON = make_jwt({"iss": "supabase", "role": "anon", "ref": "xyz"})


def names(stacks):
    return {s.name for s in stacks}


# --- Detecção pura ----------------------------------------------------------

def test_detect_firebase_from_config():
    text = 'const c={apiKey:"AIzaxxx",authDomain:"demo.firebaseapp.com",projectId:"demo"};'
    stacks = detect_stacks(text)
    fb = next(s for s in stacks if s.name == "firebase")
    assert fb.confidence == "high"


def test_detect_supabase_and_nextjs():
    text = f'createClient("https://xyz.supabase.co","{ANON}"); window.__NEXT_DATA__={{}}'
    assert {"supabase", "nextjs"} <= names(detect_stacks(text))


def test_detect_aws_from_header_and_key():
    high = detect_stacks("var k='AKIAIOSFODNN7EXAMPLE'", {"X-Amz-Cf-Id": "x"})
    aws = next(s for s in high if s.name == "aws")
    assert aws.confidence == "high"  # a presença da AKIA eleva a confiança


def test_extract_firebase_config_fields():
    text = 'firebaseConfig={apiKey:"k",projectId:"p",databaseURL:"https://p.firebaseio.com"}'
    cfg = extract_firebase_config(text)
    assert cfg["projectId"] == "p" and cfg["databaseURL"] == "https://p.firebaseio.com"


def test_extract_paths_same_origin_only():
    html = 'fetch("/api/orders");<a href="/admin">x</a><script src="https://cdn.other/app.js">' \
           'fetch("https://app.test/internal/users")'
    paths = extract_paths(html, "https://app.test")
    assert "/api/orders" in paths and "/admin" in paths and "/internal/users" in paths


def test_script_srcs_resolves_and_filters():
    html = '<script src="/_next/app.js"></script><script src="https://evil.cdn/x.js"></script>'
    assert script_srcs(html, "https://app.test") == ["https://app.test/_next/app.js"]


# --- Orquestração (HTTP injetado) -------------------------------------------

class FakeRecon(Recon):
    def __init__(self, pages):
        super().__init__("https://app.test")
        self.pages = pages
        self.scanned = []

    def _get(self, url):
        return self.pages.get(url, (200, {"Content-Type": "text/html"}, "<html>spa</html>"))

    def _scan_supabase(self, inst):
        self.scanned.append(inst.url)
        return []


def test_recon_identifies_routes_and_credentials():
    html = (
        "<html><script src='/_next/static/app.js'></script>"
        f'<script>const sb=createClient("https://xyz.supabase.co","{ANON}");'
        'const fb={apiKey:"AIzak",authDomain:"demo.firebaseapp.com",projectId:"demo",'
        'databaseURL:"https://proj.firebaseio.com"};'
        'const aws="AKIAIOSFODNN7EXAMPLE";</script></html>'
    )
    pages = {
        "https://app.test": (200, {"Content-Type": "text/html"}, html),
        # catch-all da SPA (baseline) responde 200 html:
        "https://app.test/permiscan-probe-404-xyz": (200, {"Content-Type": "text/html"}, "spa"),
        # endpoints de verdade (não-html) devem sobreviver ao filtro de catch-all:
        "https://app.test/rest/v1/": (200, {"Content-Type": "application/openapi+json"}, "{}"),
        "https://app.test/.env": (200, {"Content-Type": "application/json"}, "SECRET=1"),
        # RTDB legível sem auth:
        "https://proj.firebaseio.com/.json?shallow=true": (200, {}, '{"users":true,"config":true}'),
    }
    result = FakeRecon(pages).run()

    assert {"firebase", "supabase", "nextjs"} <= names(result.stacks)
    assert result.firebase_config["projectId"] == "demo"
    assert [i.url for i in result.supabase_instances] == ["https://xyz.supabase.co"]

    paths = {e.path for e in result.endpoints}
    assert "/rest/v1/" in paths and "/.env" in paths
    assert "/robots.txt" not in paths  # filtrado como catch-all da SPA

    rules = {f.rule_id for f in result.findings}
    assert {"firebase-rtdb-public-read", "exposed-aws-access-key", "exposed-sensitive-file"} <= rules


def test_recon_routes_supabase_instances_to_the_scanner():
    html = f'<script>createClient("https://xyz.supabase.co","{ANON}")</script>'
    fake = FakeRecon({"https://app.test": (200, {"Content-Type": "text/html"}, html)})
    fake.run()
    assert fake.scanned == ["https://xyz.supabase.co"]


def test_recon_recommends_scan_rules_when_firebase_without_findings():
    html = '<script>const c={apiKey:"k",authDomain:"d.firebaseapp.com",projectId:"demo"}</script>'
    result = FakeRecon({"https://app.test": (200, {"Content-Type": "text/html"}, html)}).run()
    assert any("scan-rules" in r for r in result.recommendations)
