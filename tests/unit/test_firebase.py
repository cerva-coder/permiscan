from pathlib import Path

import pytest

from permiscan.adapters.base import AdapterError
from permiscan.adapters.firebase import FirebaseAdapter, analyze_rules
from permiscan.findings import Confidence, Severity

LAB = Path(__file__).parents[1] / "fixtures" / "firebase"


def ids(findings):
    return {(f.rule_id, f.severity) for f in findings}


def test_firestore_vulnerable_fixture():
    found = FirebaseAdapter(LAB / "firestore_vulnerable.rules").scan()
    assert ids(found) == {
        ("firebase-rule-public", Severity.CRITICAL),              # allow read, write: if true
        ("firebase-rule-public", Severity.HIGH),                  # allow read: if true
        ("firebase-rule-any-authenticated-write", Severity.MEDIUM),
    }


def test_firestore_safe_fixture_has_no_findings():
    assert FirebaseAdapter(LAB / "firestore_safe.rules").scan() == []


def test_rtdb_fixture():
    found = FirebaseAdapter(LAB / "database_vulnerable.rules").scan()
    assert ids(found) == {
        ("firebase-rtdb-public-read", Severity.HIGH),
        ("firebase-rtdb-public-write", Severity.CRITICAL),
    }


def test_if_true_variants_are_detected_regardless_of_spacing():
    for cond in ("if true", "if  (true)", "if ((true))"):
        rule = f"match /x/{{id}} {{ allow read: {cond}; }}"
        assert [f.rule_id for f in analyze_rules(rule, "firestore", "x")] == ["firebase-rule-public"]


def test_write_with_ownership_is_not_flagged():
    rule = "match /x/{id} { allow write: if request.auth != null && request.auth.uid == resource.data.owner; }"
    assert analyze_rules(rule, "firestore", "x") == []


def test_confidence_reflects_certainty():
    pub = analyze_rules("match /x/{id} { allow read: if true; }", "firestore", "x")[0]
    weak = analyze_rules("match /x/{id} { allow write: if request.auth != null; }", "firestore", "x")[0]
    assert pub.confidence == Confidence.LIKELY
    assert weak.confidence == Confidence.POSSIBLE


def test_unrecognized_file_raises():
    with pytest.raises(AdapterError, match="nenhuma regra"):
        analyze_rules("isto não são regras do firebase", "firestore", "x.rules")


def test_service_detection_from_filename(tmp_path):
    (tmp_path / "storage.rules").write_text("x", encoding="utf-8")
    assert FirebaseAdapter(tmp_path / "storage.rules").service == "storage"
    assert FirebaseAdapter(tmp_path / "firestore.rules").service == "firestore"
    assert FirebaseAdapter(tmp_path / "x.rules", service="database").service == "rtdb"
