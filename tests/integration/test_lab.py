"""Integração contra o laboratório: docker compose up -d lab-db"""

import json
import os
from pathlib import Path

import pytest

from permiscan.adapters import PostgresAdapter, SupabaseAdapter
from permiscan.adapters.base import AdapterError
from permiscan.cli import EXIT_FAIL_ON, main
from permiscan.scope import parse_dsn

DSN = os.environ.get("PERMISCAN_LAB_DSN")
SCOPE = Path(__file__).parents[1] / "fixtures" / "lab" / "scope.toml"

pytestmark = pytest.mark.skipif(
    not DSN,
    reason="defina PERMISCAN_LAB_DSN=postgresql://permiscan_auditor:auditor-lab-only@127.0.0.1:55432/permiscan_lab",
)

SUPABASE_EXPECTED = {
    ("pg-rls-disabled", "public.invoices"),
    ("pg-rls-disabled", "public.audit_entries"),
    ("pg-policy-unrestricted", "public.profiles [policy profiles_read]"),
    ("pg-policy-unrestricted", "public.profiles [policy profiles_update]"),
    ("pg-policy-no-ownership", "public.documents [policy documents_write]"),
    ("pg-view-definer", "public.invoice_totals"),
    ("pg-matview-exposed", "public.profile_index"),
    ("pg-func-secdef-exposed", "public.all_invoices()"),
    ("pg-func-search-path", "public.all_invoices()"),
}


def test_check_runs_read_only_with_least_privilege():
    info = SupabaseAdapter(parse_dsn(DSN)).check()
    assert info["read_only"] is True
    assert info["connected_as"] == "permiscan_auditor"
    assert info["connected_as_superuser"] is False
    assert info["missing_roles"] == [] and info["missing_schemas"] == []


def test_supabase_scan_finds_exactly_the_vulnerable_objects():
    findings = SupabaseAdapter(parse_dsn(DSN)).scan()
    assert {(f.rule_id, f.resource) for f in findings} == SUPABASE_EXPECTED
    by_resource = {f.resource: f for f in findings if f.rule_id == "pg-rls-disabled"}
    assert by_resource["public.audit_entries"].evidence["ignored_policies"] == ["audit_owner"]


def test_postgres_owner_bypass_and_forced_rls():
    findings = PostgresAdapter(parse_dsn(DSN), roles=["app_user"], schemas=["app"]).scan()
    assert {(f.rule_id, f.resource) for f in findings} == {("pg-rls-owner-bypass", "app.orders")}


def test_supabase_check_rejects_targets_without_supabase_roles():
    with pytest.raises(AdapterError, match="não parece um projeto Supabase"):
        SupabaseAdapter(parse_dsn(DSN), roles=["ghost_role"]).check()


def test_wrong_password_error_is_redacted():
    bad = DSN.replace("auditor-lab-only", "wrong-pass-123")
    with pytest.raises(AdapterError) as e:
        SupabaseAdapter(parse_dsn(bad)).check()
    assert "wrong-pass-123" not in str(e.value)


def test_cli_json_report_and_fail_on(monkeypatch, tmp_path):
    monkeypatch.setenv("PERMISCAN_DSN", DSN)
    out = tmp_path / "report.json"
    code = main(["scan", "--provider", "supabase", "--scope", str(SCOPE),
                 "--format", "json", "--output", str(out), "--fail-on", "critical"])
    assert code == EXIT_FAIL_ON
    text = out.read_text(encoding="utf-8")
    report = json.loads(text)
    assert report["summary"]["critical"] == 2
    assert len(report["findings"]) == len(SUPABASE_EXPECTED)
    assert all(f["fingerprint"] and f["remediation"]["summary"] for f in report["findings"])
    assert "auditor-lab-only" not in text
