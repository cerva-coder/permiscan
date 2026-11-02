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
    def __init__(self, pages, level=2):
        super().__init__("https://app.test", level=level)
        self.pages = pages
        self.scanned = []

    SPA = "<html>spa</html>"  # resposta de catch-all da SPA (corpo idêntico em toda rota)

    def _get(self, url):
        return self.pages.get(url, (200, {"content-type": "text/html"}, self.SPA))

    def _post(self, url, data):  # nunca faz POST real em teste (signup)
        return self.pages.get(url, (400, {}, ""))

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
        "https://app.test": (200, {"content-type": "text/html"}, html),
        # baseline do catch-all == resposta padrão da SPA (FakeRecon.SPA):
        "https://app.test/permiscan-probe-404-xyz": (200, {"content-type": "text/html"}, FakeRecon.SPA),
        # endpoints de verdade (corpo diferente da baseline) sobrevivem ao filtro:
        "https://app.test/rest/v1/": (200, {"content-type": "application/openapi+json"}, "{}"),
        "https://app.test/.env": (200, {"content-type": "application/json"}, "SECRET=1"),
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


def test_spa_catch_all_is_not_reported_as_exposed_files():
    # SPA que devolve o MESMO corpo (inclusive para /.env e /.git/config): nada é finding.
    recon = FakeRecon({"https://app.test": (200, {"content-type": "text/html"}, FakeRecon.SPA)})
    result = recon.run()
    assert result.endpoints == []
    assert all(f.rule_id != "exposed-sensitive-file" for f in result.findings)


def test_firestore_and_storage_enumeration():
    html = ('<script>const c={apiKey:"AIzak",authDomain:"demo.firebaseapp.com",'
            'projectId:"demo",storageBucket:"demo.appspot.com"}</script>')
    pages = {
        "https://app.test": (200, {"content-type": "text/html"}, html),
        "https://app.test/permiscan-probe-404-xyz": (200, {"content-type": "text/html"}, FakeRecon.SPA),
        "https://firestore.googleapis.com/v1/projects/demo/databases/(default)/documents/users?pageSize=1&key=AIzak":
            (200, {}, '{"documents":[{"name":"users/1"}]}'),
        "https://firebasestorage.googleapis.com/v0/b/demo.appspot.com/o?maxResults=10":
            (200, {}, '{"items":[{"name":"a.png"}]}'),
        # nível 3 usa maxResults=100:
        "https://firebasestorage.googleapis.com/v0/b/demo.appspot.com/o?maxResults=100":
            (200, {}, '{"items":[{"name":"a.png"}]}'),
    }
    findings = {f.rule_id: f for f in FakeRecon(pages).run().findings}
    assert "firebase-firestore-public-read" in findings
    storage = findings["firebase-storage-public-list"]
    assert storage.evidence["files"] == ["a.png"]  # drill-down: lists the files
    assert "download_urls" not in storage.evidence  # level 2 doesn't extract URLs

    # nível 3 extrai as URLs de download diretas
    storage3 = {f.rule_id: f for f in FakeRecon(pages, level=3).run().findings}["firebase-storage-public-list"]
    assert storage3.evidence["download_urls"][0].endswith("a.png?alt=media")


def test_firebase_config_discovered_from_runtime_file():
    pages = {
        "https://app.test": (200, {"content-type": "text/html"}, "<html>no config</html>"),
        "https://app.test/__/firebase/init.json":
            (200, {"content-type": "application/json"}, '{"projectId":"demo","apiKey":"AIzak"}'),
    }
    assert FakeRecon(pages).run().firebase_config.get("projectId") == "demo"


def test_recon_recommends_scan_rules_when_firebase_without_findings():
    html = '<script>const c={apiKey:"k",authDomain:"d.firebaseapp.com",projectId:"demo"}</script>'
    result = FakeRecon({"https://app.test": (200, {"Content-Type": "text/html"}, html)}).run()
    assert any("scan-rules" in r for r in result.recommendations)
