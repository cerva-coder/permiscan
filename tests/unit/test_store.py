"""Persistência de alvos: dedup, status por confiança e preservação de status manual."""

from permiscan import store
from permiscan.adapters.supabase_api import DetectedInstance
from permiscan.discovery import ReconResult
from permiscan.findings import Category, Confidence, Finding, Remediation, Severity


def _finding(rule_id, resource, provider="supabase-api", conf=Confidence.CONFIRMED):
    return Finding(
        rule_id=rule_id, title="t", description="d", category=Category.AUTHORIZATION,
        provider=provider, resource=resource, severity=Severity.HIGH, confidence=conf,
        remediation=Remediation(summary="s"),
    )


def _supabase_result(resource="rest/v1/users"):
    inst = DetectedInstance("https://abcd.supabase.co", [{"key": "eyJanon", "role": "anon", "ref": "abcd"}])
    return ReconResult(target="https://app.exemplo.com", supabase_instances=[inst],
                       findings=[_finding("supabase-api-anon-read", resource)])


def test_enroll_cria_alvo_e_finding(tmp_path):
    db = tmp_path / "t.db"
    ids = store.enroll(_supabase_result(), "teste", path=db)
    assert len(ids) == 1
    t = store.get_target(ids[0], path=db)
    assert t["platform"] == "supabase" and t["project_ref"] == "abcd"
    assert t["status"] == store.STATUS_CONFIRMED  # finding confirmado
    assert len(t["findings"]) == 1 and t["findings"][0]["poc"] is None
    assert t["api_key"] == "eyJanon"  # chave anon (pública) é guardada


def test_dedup_mesmo_scan_duas_vezes_nao_duplica(tmp_path):
    db = tmp_path / "t.db"
    store.enroll(_supabase_result(), path=db)
    store.enroll(_supabase_result(), path=db)  # idempotente
    assert store.stats(path=db)["targets"] == 1
    assert store.stats(path=db)["findings"] == 1
    # re-scan gera uma segunda entrada de histórico, não um segundo finding
    assert len(store.get_target(1, path=db)["activity"]) == 2


def test_status_identificado_sem_confirmacao(tmp_path):
    db = tmp_path / "t.db"
    r = _supabase_result()
    object.__setattr__(r, "findings", [_finding("x", "rest/v1/u", conf=Confidence.POSSIBLE)])
    tid = store.enroll(r, path=db)[0]
    assert store.get_target(tid, path=db)["status"] == store.STATUS_IDENTIFIED


def test_confirmado_exige_severidade_alta_nao_so_confidence(tmp_path):
    """Finding confirmado mas leve (medium/low) não deve marcar o alvo como vuln_confirmado —
    senão a tag acende pra achado sem gravidade nenhuma."""
    db = tmp_path / "t.db"
    r = _supabase_result()
    f = _finding("supabase-api-anon-read", "rest/v1/u", conf=Confidence.CONFIRMED)
    object.__setattr__(f, "severity", Severity.MEDIUM)
    object.__setattr__(r, "findings", [f])
    tid = store.enroll(r, path=db)[0]
    t = store.get_target(tid, path=db)
    assert t["status"] == store.STATUS_IDENTIFIED
    assert store.stats(path=db)["confirmed_targets"] == 0


def test_status_manual_preservado_no_rescan(tmp_path):
    db = tmp_path / "t.db"
    tid = store.enroll(_supabase_result(), path=db)[0]
    store.update_target(tid, status="corrigido", path=db)
    store.enroll(_supabase_result(), path=db)  # re-scan não reverte para vuln_confirmado
    assert store.get_target(tid, path=db)["status"] == "corrigido"


def test_chave_service_role_nao_persistida(tmp_path):
    db = tmp_path / "t.db"
    inst = DetectedInstance("https://xy.supabase.co",
                            [{"key": "sb_secret_xxx", "role": "service_role", "ref": "xy"}])
    r = ReconResult(target="https://app", supabase_instances=[inst],
                    findings=[_finding("supabase-service-role-key", "project:xy")])
    tid = store.enroll(r, path=db)[0]
    assert store.get_target(tid, path=db)["api_key"] is None  # segredo não vai pro disco


def test_sobrevive_a_reabertura(tmp_path):
    db = tmp_path / "t.db"
    store.enroll(_supabase_result(), path=db)
    # nova "sessão": só o caminho do arquivo, nada em memória
    assert store.list_targets(path=db)[0]["project_ref"] == "abcd"
