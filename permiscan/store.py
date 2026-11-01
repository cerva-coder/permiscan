"""Persistência de alvos e findings em SQLite (stdlib).

O scanner já produz `ReconResult` com `Finding`s imutáveis e `fingerprint` estável
(`sha256(provider|rule_id|resource)`). Aqui a gente só guarda isso de forma durável e
deduplicada, para abrir o alvo depois sem rodar o scan de novo.

Deduplicação sai de graça: `targets.identity` e `findings.fingerprint` são UNIQUE/PK;
reenviar o mesmo resultado atualiza `last_seen` em vez de criar linha nova.

Chaves públicas por design (anon/publishable do Supabase, apiKey web do Firebase) são
guardadas porque são necessárias para reabrir o workspace. Chaves sensíveis
(service_role / sb_secret_) nunca são persistidas — viram None.
"""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from permiscan.adapters.supabase_api import _project_ref

if TYPE_CHECKING:
    from permiscan.discovery import ReconResult

DB_PATH = Path(__file__).resolve().parent.parent / "permiscan.db"

# Status computados a partir dos findings; os demais são definidos à mão na UI e preservados.
STATUS_IDENTIFIED = "identificado"
STATUS_CONFIRMED = "vuln_confirmado"
_MANUAL_STATUS = {"parcialmente_exploravel", "exploracao_validada", "corrigido", "arquivado"}
ALL_STATUS = [STATUS_IDENTIFIED, STATUS_CONFIRMED, *_MANUAL_STATUS]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY,
    identity TEXT UNIQUE NOT NULL,
    platform TEXT NOT NULL,
    url TEXT,
    project_ref TEXT,
    api_key TEXT,
    status TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    source TEXT,
    notes TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    rule_id TEXT, title TEXT, severity TEXT, confidence TEXT,
    category TEXT, resource TEXT, data TEXT NOT NULL,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    ts TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT
);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


# ponytail: abre uma conexão por chamada. O enroll roda em threads (scan em massa);
# conexão-por-chamada + WAL + busy_timeout evita lock sem precisar de pool.
def connect(path: Path | str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    return conn


def _safe_key(role: str | None, key: str | None) -> str | None:
    """Não persiste chave sensível; anon/publishable/web ficam (são públicas por design)."""
    if not key:
        return None
    if role == "service_role" or key.startswith("sb_secret_"):
        return None
    return key


def _targets_from_result(result: "ReconResult") -> dict[str, dict]:
    """identity -> campos do alvo, derivados do ReconResult."""
    import urllib.parse

    targets: dict[str, dict] = {}
    for inst in result.supabase_instances:
        ref = _project_ref(inst.url) or inst.url
        role = next((k["role"] for k in inst.keys if k["key"] == inst.anon_key), None)
        targets[f"supabase:{ref}"] = {
            "platform": "supabase", "url": inst.url, "project_ref": ref,
            "api_key": _safe_key(role, inst.anon_key),
        }
    cfg = result.firebase_config or {}
    pid = cfg.get("projectId")
    if pid or cfg.get("databaseURL"):
        ident = f"firebase:{pid or cfg.get('databaseURL')}"
        targets[ident] = {
            "platform": "firebase",
            "url": cfg.get("databaseURL") or (f"https://{pid}.firebaseapp.com" if pid else result.target),
            "project_ref": pid, "api_key": cfg.get("apiKey"),  # apiKey web do Firebase é pública
        }
    # Alvo "site" só se houver finding que não pertença a um BaaS (chave AWS, arquivo exposto).
    if any(f.provider in ("aws", "http") for f in result.findings):
        host = urllib.parse.urlsplit(result.target).netloc or result.target
        targets[f"site:{host}"] = {"platform": "site", "url": result.target,
                                   "project_ref": None, "api_key": None}
    return targets


def _finding_identity(finding, targets: dict[str, dict], result: "ReconResult") -> str | None:
    """Casa um finding com a identity do alvo a que pertence."""
    import urllib.parse

    p = finding.provider
    if p.startswith("supabase"):
        sb = [k for k in targets if k.startswith("supabase:")]
        ref = finding.evidence.get("ref") or finding.evidence.get("project_ref")
        match = next((k for k in sb if ref and k == f"supabase:{ref}"), None)
        return match or (sb[0] if sb else None)
    if p == "firebase":
        return next((k for k in targets if k.startswith("firebase:")), None)
    host = urllib.parse.urlsplit(result.target).netloc or result.target
    return f"site:{host}" if f"site:{host}" in targets else None


def _status_for(existing: str | None, findings) -> str:
    if existing in _MANUAL_STATUS:
        return existing  # transição manual não é sobrescrita por re-scan
    confirmed = any(f.confidence.value == "confirmed" for f in findings)
    return STATUS_CONFIRMED if confirmed else STATUS_IDENTIFIED


def enroll(result: "ReconResult", source: str = "", path: Path | str = DB_PATH) -> list[int]:
    """Cadastra/atualiza os alvos do ReconResult e seus findings. Idempotente.

    Retorna os ids dos alvos tocados. Só cria alvo que tenha pelo menos um finding.
    """
    targets = _targets_from_result(result)
    if not targets or not result.findings:
        return []

    by_target: dict[str, list] = {ident: [] for ident in targets}
    for f in result.findings:
        ident = _finding_identity(f, targets, result)
        if ident:
            by_target[ident].append(f)

    now = _now()
    touched: list[int] = []
    conn = connect(path)
    try:
        for ident, fields in targets.items():
            fs = by_target[ident]
            if not fs:
                continue
            row = conn.execute("SELECT id, status FROM targets WHERE identity=?", (ident,)).fetchone()
            status = _status_for(row["status"] if row else None, fs)
            if row:
                tid = row["id"]
                conn.execute(
                    "UPDATE targets SET url=?, project_ref=?, api_key=COALESCE(?, api_key), "
                    "status=?, last_seen=?, source=? WHERE id=?",
                    (fields["url"], fields["project_ref"], fields["api_key"], status, now, source, tid),
                )
            else:
                cur = conn.execute(
                    "INSERT INTO targets (identity, platform, url, project_ref, api_key, status, "
                    "first_seen, last_seen, source) VALUES (?,?,?,?,?,?,?,?,?)",
                    (ident, fields["platform"], fields["url"], fields["project_ref"],
                     fields["api_key"], status, now, now, source),
                )
                tid = cur.lastrowid
            touched.append(tid)
            for f in fs:
                conn.execute(
                    "INSERT INTO findings (fingerprint, target_id, rule_id, title, severity, "
                    "confidence, category, resource, data, first_seen, last_seen) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(fingerprint) DO UPDATE SET last_seen=excluded.last_seen, "
                    "data=excluded.data, severity=excluded.severity, confidence=excluded.confidence",
                    (f.fingerprint, tid, f.rule_id, f.title, f.severity.value, f.confidence.value,
                     f.category.value, f.resource, json.dumps(f.model_dump(mode="json"), ensure_ascii=False),
                     now, now),
                )
            conn.execute("INSERT INTO activity (target_id, ts, kind, detail) VALUES (?,?,?,?)",
                         (tid, now, "scan", f"{source or 'scan'}: {len(fs)} finding(s)"))
        conn.commit()
    finally:
        conn.close()
    return touched


# --- Leitura (consumida pelo servidor web) ----------------------------------


def stats(path: Path | str = DB_PATH) -> dict:
    conn = connect(path)
    try:
        by_platform = {r["platform"]: r["n"] for r in
                       conn.execute("SELECT platform, COUNT(*) n FROM targets GROUP BY platform")}
        by_status = {r["status"]: r["n"] for r in
                     conn.execute("SELECT status, COUNT(*) n FROM targets GROUP BY status")}
        confirmed = conn.execute(
            "SELECT COUNT(DISTINCT target_id) n FROM findings WHERE confidence='confirmed'").fetchone()["n"]
        return {
            "targets": conn.execute("SELECT COUNT(*) n FROM targets").fetchone()["n"],
            "findings": conn.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"],
            "confirmed_targets": confirmed,
            "by_platform": by_platform, "by_status": by_status,
        }
    finally:
        conn.close()


def list_targets(path: Path | str = DB_PATH) -> list[dict]:
    conn = connect(path)
    try:
        rows = conn.execute("""
            SELECT t.*, COUNT(f.fingerprint) findings,
                   SUM(f.severity='critical') crit, SUM(f.severity='high') high
            FROM targets t LEFT JOIN findings f ON f.target_id=t.id
            GROUP BY t.id ORDER BY t.last_seen DESC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_target(tid: int, path: Path | str = DB_PATH) -> dict | None:
    conn = connect(path)
    try:
        t = conn.execute("SELECT * FROM targets WHERE id=?", (tid,)).fetchone()
        if not t:
            return None
        findings = [json.loads(r["data"]) for r in conn.execute(
            "SELECT data FROM findings WHERE target_id=? ORDER BY severity", (tid,))]
        activity = [dict(r) for r in conn.execute(
            "SELECT ts, kind, detail FROM activity WHERE target_id=? ORDER BY ts DESC", (tid,))]
        return {**dict(t), "findings": findings, "activity": activity}
    finally:
        conn.close()


def update_target(tid: int, *, status: str | None = None, notes: str | None = None,
                  path: Path | str = DB_PATH) -> bool:
    conn = connect(path)
    try:
        if not conn.execute("SELECT 1 FROM targets WHERE id=?", (tid,)).fetchone():
            return False
        if status is not None:
            if status not in ALL_STATUS:
                raise ValueError(f"status inválido: {status}")
            conn.execute("UPDATE targets SET status=? WHERE id=?", (status, tid))
            conn.execute("INSERT INTO activity (target_id, ts, kind, detail) VALUES (?,?,?,?)",
                         (tid, _now(), "status", status))
        if notes is not None:
            conn.execute("UPDATE targets SET notes=? WHERE id=?", (notes, tid))
        conn.commit()
        return True
    finally:
        conn.close()
