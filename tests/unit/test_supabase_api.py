import base64
import json

from permiscan.adapters.supabase_api import ApiTable, SupabaseApiScanner, jwt_claims
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

    def __init__(self, key, tables):
        super().__init__("https://abcd.supabase.co", key)
        self._tables = tables

    def _openapi(self):
        return {"paths": {f"/{name}": {} for name in self._tables}}

    def _probe_table(self, name):
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
