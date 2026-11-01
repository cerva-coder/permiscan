import base64
import json

from permiscan.adapters.supabase_api import (
    ApiScanOptions,
    ApiTable,
    SupabaseApiScanner,
    detect_instances,
    jwt_claims,
    rpc_risk,
)
from permiscan.findings import Confidence, Severity
from permiscan.sensitivity import field_severity, most_sensitive


def make_jwt(claims: dict) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJIUzI1NiJ9.{payload}.sig"


def test_jwt_claims_decodes_role_and_ref():
    token = make_jwt({"role": "anon", "ref": "abcd"})
    assert jwt_claims(token) == {"role": "anon", "ref": "abcd"}
    assert jwt_claims("not-a-jwt") == {}


def test_openapi_separates_tables_from_rpcs():
    spec = {"paths": {"/": {}, "/invoices": {}, "/profiles": {}, "/rpc/do_admin": {}, "/_meta": {}, "/x/{id}": {}}}
    assert SupabaseApiScanner._tables_and_rpcs(spec) == (["invoices", "profiles"], ["do_admin"])


def test_sensitivity_classification():
    assert field_severity("password") == Severity.CRITICAL
    assert field_severity("email") == Severity.HIGH
    assert field_severity("cpf") == Severity.HIGH
    assert field_severity("endereco") == Severity.MEDIUM
    assert field_severity("id") == Severity.INFO
    assert field_severity("created_at") == Severity.INFO
    sev, flagged = most_sensitive(["id", "nome", "senha", "email"])
    assert sev == Severity.CRITICAL and set(flagged) == {"senha", "email"}


class StubScanner(SupabaseApiScanner):
    """Substitui a camada HTTP para testar a lógica de findings sem rede."""

    def __init__(self, key, tables, options=None):
        super().__init__("https://abcd.supabase.co", key, options)
        self._tables = tables

    def _openapi(self):
        return {"paths": {f"/{name}": {} for name in self._tables}}

    def _probe_table(self, name, rows):
        return self._tables[name]


def test_service_role_key_is_a_critical_finding():
    scanner = StubScanner(make_jwt({"role": "service_role", "ref": "abcd"}), {})
    found = scanner.scan()
    assert [(f.rule_id, f.severity) for f in found] == [("supabase-service-role-key", Severity.CRITICAL)]
    assert found[0].confidence == Confidence.CONFIRMED


def test_anon_readable_table_scales_with_column_sensitivity():
    scanner = StubScanner(make_jwt({"role": "anon", "ref": "abcd"}), {
        "invoices": ApiTable("invoices", ("id", "amount", "password"), 42),
        "public_posts": ApiTable("public_posts", ("id", "title"), 3),
        "locked": None,  # anon não conseguiu ler
    })
    by_resource = {f.resource: f for f in scanner.scan()}
    assert set(by_resource) == {"rest/v1/invoices", "rest/v1/public_posts"}
    sensitive = by_resource["rest/v1/invoices"]
    assert sensitive.severity == Severity.CRITICAL
    assert sensitive.confidence == Confidence.CONFIRMED
    assert sensitive.evidence["sensitive_columns"] == ["password"]
    assert sensitive.evidence["row_count"] == 42
    # Nenhum valor de linha é guardado como evidência, só os nomes das colunas.
    assert "amount" not in json.dumps(sensitive.evidence) or sensitive.evidence["columns"] == ["id", "amount", "password"]
    assert by_resource["rest/v1/public_posts"].severity == Severity.MEDIUM


def test_rpc_risk_by_name():
    assert rpc_risk("delete_user") == Severity.CRITICAL
    assert rpc_risk("admin_reset") == Severity.CRITICAL
    assert rpc_risk("send_email") == Severity.HIGH
    assert rpc_risk("get_profile") == Severity.MEDIUM
    assert rpc_risk("ping") == Severity.LOW


def test_detect_pairs_keys_to_projects_by_ref():
    anon = make_jwt({"iss": "supabase", "role": "anon", "ref": "abcd"})
    text = f'const url="https://abcd.supabase.co"; const key="{anon}"; const sb="sb_secret_DEADBEEF12345";'
    [inst] = detect_instances(text)
    assert inst.url == "https://abcd.supabase.co"
    roles = {k["role"] for k in inst.keys}
    assert "anon" in roles and "service_role" in roles  # sb_secret_ casa por ser a única URL
    assert inst.anon_key == anon


def test_detect_ignores_non_supabase_jwt():
    assert detect_instances("token=eyJhbGci.eyJzdWIiOiIxIn0.sig sem url") == []


# --- Interpretação das respostas HTTP de escrita e RPC ----------------------

class FakeHTTP(SupabaseApiScanner):
    def __init__(self, responses, options=None):
        super().__init__("https://abcd.supabase.co", make_jwt({"role": "anon", "ref": "abcd"}), options)
        self.responses = responses

    def _request(self, path, *, method="GET", headers=None, data=None):
        return self.responses[(method, path)]


def _resp(status, message=""):
    body = json.dumps({"message": message}).encode() if message else b""
    return (status, {}, body)


def test_write_probe_interpretation():
    assert FakeHTTP({("POST", "/t"): _resp(201)})._test_write("t") == "inserted"
    # 4xx por constraint = RLS deixou passar
    assert FakeHTTP({("POST", "/t"): _resp(400, "null value in column x violates not-null")})._test_write("t") == "allowed"
    assert FakeHTTP({("POST", "/t"): _resp(401, "permission denied")})._test_write("t") == "blocked"
    assert FakeHTTP({("POST", "/t"): _resp(403, 'new row violates row-level security policy')})._test_write("t") == "blocked"


def test_rpc_probe_interpretation():
    assert FakeHTTP({("POST", "/rpc/f"): _resp(200)})._test_rpc("f") == "accessible"
    assert FakeHTTP({("POST", "/rpc/f"): _resp(400, "missing required parameter uid")})._test_rpc("f") == "accessible"
    assert FakeHTTP({("POST", "/rpc/f"): _resp(401, "permission denied")})._test_rpc("f") == "blocked"
    assert FakeHTTP({("POST", "/rpc/f"): _resp(404, "could not find function")})._test_rpc("f") == "unknown"


def test_destructive_rpc_is_not_called_without_opt_in():
    tables_spec = {"paths": {"/rpc/delete_all": {}, "/rpc/get_stats": {}}}

    class RpcScanner(SupabaseApiScanner):
        def __init__(self, options):
            super().__init__("https://abcd.supabase.co", make_jwt({"role": "anon", "ref": "abcd"}), options)
            self.called = []

        def _openapi(self):
            return tables_spec

        def _test_rpc(self, name):
            self.called.append(name)
            return "accessible"

    guarded = RpcScanner(ApiScanOptions(probe_rpc=True))
    found = {f.rule_id for f in guarded.scan()}
    assert "delete_all" not in guarded.called                      # destrutiva não foi chamada
    assert "supabase-api-rpc-exposed" in found                     # mas aparece como "não chamada"
    assert "supabase-api-anon-rpc" in found                        # get_stats foi chamada e é finding

    loud = RpcScanner(ApiScanOptions(probe_rpc=True, include_destructive=True))
    loud.scan()
    assert "delete_all" in loud.called                             # com a flag, é chamada
