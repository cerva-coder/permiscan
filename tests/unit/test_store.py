"""Target persistence: dedup, confidence-based status, and manual status preservation."""

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
    return ReconResult(target="https://app.example.com", supabase_instances=[inst],
                       findings=[_finding("supabase-api-anon-read", resource)])


def test_enroll_creates_target_and_finding(tmp_path):
    db = tmp_path / "t.db"
    ids = store.enroll(_supabase_result(), "test", path=db)
    assert len(ids) == 1
    t = store.get_target(ids[0], path=db)
    assert t["platform"] == "supabase" and t["project_ref"] == "abcd"
    assert t["status"] == store.STATUS_CONFIRMED  # confirmed finding
    assert len(t["findings"]) == 1 and t["findings"][0]["poc"] is None
    assert t["api_key"] == "eyJanon"  # the (public) anon key is stored


def test_dedup_same_scan_twice_does_not_duplicate(tmp_path):
    db = tmp_path / "t.db"
    store.enroll(_supabase_result(), path=db)
    store.enroll(_supabase_result(), path=db)  # idempotent
    assert store.stats(path=db)["targets"] == 1
    assert store.stats(path=db)["findings"] == 1
    # a re-scan creates a second activity entry, not a second finding
    assert len(store.get_target(1, path=db)["activity"]) == 2


def test_status_identified_without_confirmation(tmp_path):
    db = tmp_path / "t.db"
    r = _supabase_result()
    object.__setattr__(r, "findings", [_finding("x", "rest/v1/u", conf=Confidence.POSSIBLE)])
    tid = store.enroll(r, path=db)[0]
    assert store.get_target(tid, path=db)["status"] == store.STATUS_IDENTIFIED


def test_confirmed_requires_high_severity_not_just_confidence(tmp_path):
    """A confirmed but low-severity (medium/low) finding shouldn't mark the target as
    vuln_confirmed — otherwise the tag lights up for a finding with no real severity."""
    db = tmp_path / "t.db"
    r = _supabase_result()
    f = _finding("supabase-api-anon-read", "rest/v1/u", conf=Confidence.CONFIRMED)
    object.__setattr__(f, "severity", Severity.MEDIUM)
    object.__setattr__(r, "findings", [f])
    tid = store.enroll(r, path=db)[0]
    t = store.get_target(tid, path=db)
    assert t["status"] == store.STATUS_IDENTIFIED
    assert store.stats(path=db)["confirmed_targets"] == 0


def test_manual_status_preserved_on_rescan(tmp_path):
    db = tmp_path / "t.db"
    tid = store.enroll(_supabase_result(), path=db)[0]
    store.update_target(tid, status="fixed", path=db)
    store.enroll(_supabase_result(), path=db)  # re-scan doesn't revert to vuln_confirmed
    assert store.get_target(tid, path=db)["status"] == "fixed"


def test_service_role_key_not_persisted(tmp_path):
    db = tmp_path / "t.db"
    inst = DetectedInstance("https://xy.supabase.co",
                            [{"key": "sb_secret_xxx", "role": "service_role", "ref": "xy"}])
    r = ReconResult(target="https://app", supabase_instances=[inst],
                    findings=[_finding("supabase-service-role-key", "project:xy")])
    tid = store.enroll(r, path=db)[0]
    assert store.get_target(tid, path=db)["api_key"] is None  # the secret never hits disk


def test_survives_reopening(tmp_path):
    db = tmp_path / "t.db"
    store.enroll(_supabase_result(), path=db)
    # new "session": just the file path, nothing in memory
    assert store.list_targets(path=db)[0]["project_ref"] == "abcd"
