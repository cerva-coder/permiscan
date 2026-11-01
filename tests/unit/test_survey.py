import json
from pathlib import Path

from permiscan import survey
from permiscan.adapters.supabase_api import DetectedInstance
from permiscan.discovery import ReconResult, StackSignal


class FakeRecon:
    def __init__(self, url, level=2, options=None):
        self.url = url

    def run(self):
        r = ReconResult(self.url)
        if "sb" in self.url:
            r.stacks = [StackSignal("supabase", "high")]
            r.supabase_instances = [DetectedInstance("https://x.supabase.co")]
        elif "boom" in self.url:
            raise RuntimeError("falhou")
        return r


def test_has_resources():
    assert survey.has_resources({"firebase_project": "p"})
    assert survey.has_resources({"supabase": ["u"]})
    assert survey.has_resources({"findings": [{"rule_id": "x"}]})
    assert not survey.has_resources({"stacks": ["nextjs"], "supabase": [], "findings": []})


def test_survey_many_triages_and_sorts_interesting_first(monkeypatch):
    monkeypatch.setattr(survey, "Recon", FakeRecon)
    recs = survey.survey_many(["http://plain", "http://sb-site", "http://boom"], level=1, workers=4)
    assert len(recs) == 3
    by_url = {r["url"]: r for r in recs}
    assert survey.has_resources(by_url["http://sb-site"])
    assert not survey.has_resources(by_url["http://plain"])
    assert by_url["http://boom"]["error"] == "falhou"
    # Os com recursos vêm primeiro na ordenação.
    assert recs[0]["url"] == "http://sb-site"


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(survey, "Recon", FakeRecon)
    recs = survey.survey_many(["http://sb-site"], level=1)
    p = tmp_path / "survey.json"
    survey.save_survey(recs, p)
    assert json.loads(p.read_text(encoding="utf-8"))[0]["url"] == "http://sb-site"
    assert survey.load_survey(p) == recs


def test_load_urls_skips_blanks_and_comments(tmp_path):
    p = tmp_path / "urls.txt"
    p.write_text("https://a\n\n# comentário\n  https://b  \n", encoding="utf-8")
    assert survey.load_urls(p) == ["https://a", "https://b"]
