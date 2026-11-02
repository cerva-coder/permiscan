"""Mass scan: triage a list of sites and explore the saved list in depth.

Triage (low level, fast, parallel) identifies which sites have Firebase/Supabase and
their endpoints, and saves that to JSON. The saved list can then be explored in depth.
"""

import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from permiscan.discovery import Recon, ReconResult


def _record(url: str, result: ReconResult | None, error: str | None) -> dict:
    if result is None:
        return {"url": url, "error": error}
    return {
        "url": url,
        "stacks": [s.name for s in result.stacks],
        "firebase_project": result.firebase_config.get("projectId"),
        "supabase": [i.url for i in result.supabase_instances],
        "endpoints": [e.path for e in result.endpoints],
        "severity_counts": dict(Counter(f.severity.value for f in result.findings)),
        "findings": [{"rule_id": f.rule_id, "severity": f.severity.value,
                      "title": f.title, "resource": f.resource} for f in result.findings],
    }


def has_resources(rec: dict) -> bool:
    """Has a relevant backend (or any finding) that justifies exploring in depth?"""
    return bool(rec.get("firebase_project") or rec.get("supabase") or rec.get("findings"))


def survey_many(urls: list[str], level: int = 1, workers: int = 8, progress=None) -> list[dict]:
    def work(u: str) -> dict:
        try:
            result = Recon(u, level=level).run()
            from permiscan import store
            store.enroll(result, "triage")  # a vulnerable target found in the batch is saved right away
            return _record(u, result, None)
        except Exception as e:  # noqa: BLE001 — one broken site shouldn't fail the whole batch
            return _record(u, None, str(e))

    records: list[dict] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = {ex.submit(work, u): u for u in urls}
        for i, fut in enumerate(as_completed(futures), 1):
            rec = fut.result()
            if progress:
                progress(i, len(urls), rec)
            records.append(rec)
    records.sort(key=lambda r: (not has_resources(r), r["url"]))
    return records


SCANS_DIR = Path(__file__).resolve().parent.parent / "scans"


def list_scans() -> list[Path]:
    """Saved scans (001.json, 002.json, …) in numeric order."""
    SCANS_DIR.mkdir(exist_ok=True)
    return sorted(SCANS_DIR.glob("[0-9]*.json"))


def next_scan_path() -> Path:
    """Next free numeric name under scans/ (001.json, 002.json, …)."""
    nums = [int(p.stem) for p in list_scans() if p.stem.isdigit()]
    return SCANS_DIR / f"{(max(nums) + 1) if nums else 1:03d}.json"


def save_survey(records: list[dict], path: Path) -> None:
    path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")


def load_survey(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_urls(path: Path) -> list[str]:
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]
