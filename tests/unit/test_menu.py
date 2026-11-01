from argparse import Namespace
from pathlib import Path

import pytest

from permiscan import menu


@pytest.fixture
def answers(monkeypatch):
    """Alimenta input() com uma fila de respostas e captura o que o menu despacha."""
    def drive(seq, captured):
        it = iter(seq)
        monkeypatch.setattr("builtins.input", lambda _prompt="": next(it))
        monkeypatch.setattr(menu, "dispatch", lambda ns: captured.append(ns) or 0)
    return drive


def test_scan_rules_flow_builds_expected_namespace(answers):
    captured = []
    # escolha=5, caminho, serviço(vazio), formato(vazio), salvar(vazio), outra?=n
    answers(["5", "firestore.rules", "", "", "", "n"], captured)
    assert menu.run_menu() == 0
    [ns] = captured
    assert (ns.command, ns.rules, ns.service, ns.format, ns.output) == (
        "scan-rules", Path("firestore.rules"), None, "text", None)


def test_scan_api_flow_sets_key_env_and_probes(answers, monkeypatch):
    captured = []
    monkeypatch.delenv("PERMISCAN_ANON_KEY", raising=False)
    # escolha=2, url, chave, linhas, escrita?=s, rpc?=s, destrutivo?=n, formato, salvar, outra?=n
    answers(["2", "https://x.supabase.co", "anon-key-123", "5", "s", "s", "n", "", "", "n"], captured)
    assert menu.run_menu() == 0
    [ns] = captured
    assert ns.command == "scan-api" and ns.url == "https://x.supabase.co"
    assert ns.rows == 5 and ns.probe_writes and ns.probe_rpc and not ns.include_destructive
    import os
    assert os.environ["PERMISCAN_ANON_KEY"] == "anon-key-123"


def test_invalid_option_does_not_dispatch_then_exits(answers):
    captured = []
    answers(["9", "0"], captured)
    assert menu.run_menu() == 0
    assert captured == []


def test_cancel_required_field_aborts_action(answers):
    captured = []
    # escolha=1 (recon), url vazia, "tentar de novo?"=n -> cancela, depois sai
    answers(["1", "", "n", "0"], captured)
    assert menu.run_menu() == 0
    assert captured == []


def test_ask_bool_parsing(monkeypatch):
    for raw, default, expected in [("s", False, True), ("sim", False, True), ("n", True, False),
                                   ("", True, True), ("", False, False), ("yes", False, True)]:
        monkeypatch.setattr("builtins.input", lambda _p="", r=raw: r)
        assert menu._ask_bool("x", default) is expected


def test_loop_runs_two_actions(answers):
    captured = []
    # scan-rules, outra?=s, scan-rules de novo, outra?=n
    answers(["5", "a.rules", "", "", "", "s", "5", "b.rules", "", "", "", "n"], captured)
    assert menu.run_menu() == 0
    assert [str(ns.rules) for ns in captured] == ["a.rules", "b.rules"]


def test_namespace_has_all_fields_dispatch_may_touch():
    # Garante que o Namespace do menu tem os mesmos atributos que a CLI por argumentos define.
    ns = Namespace(**menu._DEFAULTS)
    for attr in ("command", "provider", "scope", "dsn_env", "roles", "schemas", "url", "key_env",
                 "rows", "probe_writes", "probe_rpc", "include_destructive", "format", "output",
                 "fail_on", "rules", "service", "file", "scan"):
        assert hasattr(ns, attr)
