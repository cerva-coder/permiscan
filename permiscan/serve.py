"""Plataforma web local: dashboard e workspace de exploração sobre o banco de alvos.

Servidor da stdlib (`http.server`), sem framework nem Node. Serve uma página única
(HTML/JS embutido) que consome uma API JSON lendo o SQLite de `store.py`. Tudo em
127.0.0.1 — é a sua máquina olhando os seus próprios resultados de scan.

Escrita só no banco local (status/notas). O re-scan reexecuta os mesmos probes
NÃO destrutivos do scanner (nível 2: sem escrita, sem RPC destrutiva).
"""

import html as _html
import json
import re
import threading
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from permiscan import explore, store

# ponytail: progresso de scan em massa só em memória (dict simples); reinício do servidor
# perde o job em andamento — aceitável pra ferramenta local de um usuário só.
_JOBS: dict[str, dict] = {}


def scan_one(url: str, level: int = 2) -> int:
    """Scan individual disparado pela web. Retorna o nº de findings."""
    from permiscan.discovery import Recon

    url = url.strip()
    if not url:
        raise ValueError("informe uma URL")
    result = Recon(url, level=min(max(level, 1), 3)).run()
    store.enroll(result, source="web-individual")
    return len(result.findings)


def start_mass_scan(urls: list[str], level: int = 1) -> str:
    """Dispara a triagem em massa (mesmo motor do CLI) numa thread e devolve um job_id p/ polling."""
    from permiscan.survey import has_resources, next_scan_path, save_survey, survey_many

    job_id = uuid.uuid4().hex[:8]
    _JOBS[job_id] = {"total": len(urls), "done": 0, "found": 0, "finished": False, "error": None}

    def progress(i, _total, rec):
        _JOBS[job_id]["done"] = i
        if has_resources(rec):
            _JOBS[job_id]["found"] += 1

    def run():
        try:
            records = survey_many(urls, level=min(max(level, 1), 3), progress=progress)
            path = next_scan_path()
            save_survey(records, path)
            _JOBS[job_id]["file"] = path.name
        except Exception as e:  # noqa: BLE001 — job em background: erro vai pro status, não derruba nada
            _JOBS[job_id]["error"] = str(e)
        finally:
            _JOBS[job_id]["finished"] = True

    threading.Thread(target=run, daemon=True).start()
    return job_id


def rescan(target: dict, level: int = 2) -> int:
    """Reexecuta os probes não destrutivos para um alvo e reenrola. Retorna o nº de findings."""
    from permiscan.discovery import Recon, ReconResult, options_for_level
    from permiscan.adapters.supabase_api import DetectedInstance, SupabaseApiScanner

    level = min(level, 2)  # a UI nunca dispara escrita/destrutivo
    plat, url, key = target["platform"], target.get("url"), target.get("api_key")

    if plat == "supabase" and url and key:
        findings = SupabaseApiScanner(url, key, options_for_level(level)).scan()
        result = ReconResult(target=url, findings=findings,
                             supabase_instances=[DetectedInstance(url, [{"key": key, "role": "anon",
                                                 "ref": target.get("project_ref")}])])
    elif plat == "firebase":
        cfg = {"projectId": target.get("project_ref"), "apiKey": key,
               "databaseURL": url if url and "firebaseio" in url else None}
        r = Recon(url or "https://x.invalid", level=level)
        findings = r._enumerate_firebase({k: v for k, v in cfg.items() if v})
        result = ReconResult(target=url or "", findings=findings, firebase_config=cfg)
    elif url:
        result = Recon(url, level=level).run()
    else:
        return 0

    store.enroll(result, source="rescan-web")
    return len(result.findings)


# --- API ---------------------------------------------------------------------


def _handle_api(path: str, method: str, body: dict) -> tuple[int, dict]:
    parts = [p for p in path.split("/") if p]  # ['api', ...]
    if parts == ["api", "stats"]:
        return 200, store.stats()
    if parts == ["api", "targets"]:
        return 200, {"targets": store.list_targets()}
    if parts == ["api", "scan"] and method == "POST":
        try:
            n = scan_one(body.get("url", ""), int(body.get("level", 2)))
        except Exception as e:  # noqa: BLE001 — erro de scan vira resposta, não 500
            return 502, {"error": str(e)}
        return 200, {"ok": True, "findings": n}
    if parts == ["api", "scan", "mass"] and method == "POST":
        urls = [u.strip() for u in body.get("urls", []) if u and u.strip()]
        if not urls:
            return 400, {"error": "informe ao menos uma URL"}
        job_id = start_mass_scan(urls, int(body.get("level", 1)))
        return 200, {"job_id": job_id, "total": len(urls)}
    if len(parts) == 4 and parts[:3] == ["api", "scan", "mass"]:
        job = _JOBS.get(parts[3])
        return (200, job) if job else (404, {"error": "job desconhecido"})
    if len(parts) >= 3 and parts[0] == "api" and parts[1] == "targets" and parts[2].isdigit():
        tid = int(parts[2])
        sub = parts[3] if len(parts) > 3 else None
        t = store.get_target(tid)
        if not t:
            return 404, {"error": "alvo não encontrado"}

        if sub == "rescan" and method == "POST":
            try:
                n = rescan(t)
            except Exception as e:  # noqa: BLE001 — devolve o erro à UI, não derruba o servidor
                return 502, {"error": str(e)}
            return 200, {"ok": True, "findings": n, "target": store.get_target(tid)}

        if sub == "resources" and method == "GET":
            return _live(lambda: explore.resources(t))
        if sub == "rows" and method == "POST":
            return _live(lambda: _rows(t, body))
        if sub == "authz" and method == "POST":
            return _live(lambda: _authz(t, body))

        if sub is None and method == "POST":
            store.update_target(tid, status=body.get("status"), notes=body.get("notes"))
            return 200, store.get_target(tid)
        if sub is None:
            return 200, t
    return 404, {"error": "rota desconhecida"}


def _live(fn):
    """Executa uma chamada ao alvo, devolvendo erro de rede como 502 em vez de 500."""
    from permiscan.adapters.base import AdapterError
    try:
        return 200, fn()
    except AdapterError as e:
        return 502, {"error": str(e)}


def _rows(t: dict, body: dict) -> dict:
    kind = body.get("type")
    if kind == "supabase_table":
        return explore.supabase_rows(t, body["resource"], select=body.get("select", "*"),
                                     filters=body.get("filters"), order=body.get("order"),
                                     limit=int(body.get("limit", 50)), offset=int(body.get("offset", 0)))
    if kind == "firestore":
        return explore.firestore_docs(t, body["resource"])
    if kind == "rtdb":
        return explore.rtdb_get(t, body.get("path", ""), shallow=body.get("shallow", True))
    if kind == "storage":
        return explore.storage_list(t, body.get("prefix", ""), bucket=body.get("bucket"))
    return {"error": f"tipo desconhecido: {kind}"}


def _authz(t: dict, body: dict) -> dict:
    mode = body.get("mode")
    if mode == "write":
        if not body.get("allow_write"):
            return {"error": "escrita precisa de confirmação explícita (allow_write)"}
        return explore.supabase_write_test(t, body["resource"])
    if mode == "diff":
        return explore.supabase_diff(t, body["resource"],
                                     create_test_user=bool(body.get("create_test_user")))
    return {"error": f"modo desconhecido: {mode}"}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silencia o log por requisição
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            self._send(200, _PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return
        m = re.match(r"/api/targets/(\d+)/report\.(html|json)$", path)
        if m:
            t = store.get_target(int(m.group(1)))
            if not t:
                self._json(404, {"error": "alvo não encontrado"})
                return
            if m.group(2) == "json":
                body = json.dumps(t, ensure_ascii=False, indent=2).encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")
            else:
                self._send(200, report_html(t).encode("utf-8"), "text/html; charset=utf-8")
            return
        if path.startswith("/api/"):
            try:
                code, obj = _handle_api(path, "GET", {})
            except Exception as e:  # noqa: BLE001
                code, obj = 500, {"error": str(e)}
            self._json(code, obj)
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {}
        try:
            code, obj = _handle_api(path, "POST", body)
        except Exception as e:  # noqa: BLE001
            code, obj = 500, {"error": str(e)}
        self._json(code, obj)


def serve(host: str = "127.0.0.1", port: int = 8080, open_browser: bool = True) -> None:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}"
    print(f"PermiScan web em {url}  (Ctrl+C para parar)")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nencerrado.")
    finally:
        httpd.server_close()


# --- Relatório técnico (HTML pronto para impressão → PDF via navegador) ------


def report_html(t: dict) -> str:
    e = _html.escape
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(t["findings"], key=lambda f: sev_rank.get(f["severity"], 9))
    blocks = []
    for f in findings:
        ev = f"<pre>{e(json.dumps(f.get('evidence', {}), ensure_ascii=False, indent=2))}</pre>" if f.get("evidence") else ""
        poc = f"<h4>PoC</h4><pre>{e(f['poc'])}</pre>" if f.get("poc") else ""
        rem = f"<h4>Remediação</h4><p>{e((f.get('remediation') or {}).get('summary', ''))}</p>" if f.get("remediation") else ""
        blocks.append(
            f"<div class='f {e(f['severity'])}'><h3>{e(f['title'])} "
            f"<span class='b'>{e(f['severity'])} · {e(f['confidence'])}</span></h3>"
            f"<p class='m'>{e(f['rule_id'])} · {e(f['resource'])}{' · ' + e(f['cwe']) if f.get('cwe') else ''}</p>"
            f"<p>{e(f['description'])}</p>{ev}{poc}{rem}</div>")
    return f"""<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
<title>Relatório PermiScan · {e(t['project_ref'] or t['url'] or '')}</title><style>
body{{font:14px/1.5 system-ui,sans-serif;max-width:820px;margin:24px auto;padding:0 16px;color:#111}}
h1{{margin-bottom:4px}}.meta{{color:#555;margin-bottom:20px}}
.f{{border:1px solid #ddd;border-left-width:4px;border-radius:6px;padding:12px 14px;margin:14px 0;page-break-inside:avoid}}
.f.critical{{border-left-color:#d00}}.f.high{{border-left-color:#e67700}}.f.medium{{border-left-color:#b59000}}
.f.low{{border-left-color:#1565c0}}.f.info{{border-left-color:#888}}
.f h3{{margin:0 0 4px;font-size:16px}}.b{{font-size:12px;color:#666;font-weight:400}}
.m{{color:#777;font-size:12px;margin:2px 0 8px}}h4{{margin:10px 0 4px;font-size:13px}}
pre{{background:#f6f8fa;border:1px solid #e1e4e8;border-radius:6px;padding:8px;overflow:auto;
white-space:pre-wrap;word-break:break-all;font:12px ui-monospace,monospace}}
@media print{{a{{display:none}}}}
</style></head><body>
<h1>Relatório PermiScan</h1>
<div class="meta">{e(t['platform'])} · <b>{e(t['project_ref'] or '')}</b><br>{e(t['url'] or '')}<br>
status: {e(t['status'])} · {len(findings)} finding(s) · descoberto {e((t['first_seen'] or '')[:19])}</div>
{e(t['notes']) and f'<p><b>Anotações:</b> {e(t["notes"])}</p>' or ''}
{''.join(blocks) or '<p>Sem findings.</p>'}
<p style="margin-top:30px;color:#999;font-size:12px">Gerado pelo PermiScan · imprima esta página (Ctrl+P) para exportar em PDF.</p>
</body></html>"""


# --- Página (SPA de arquivo único, tema escuro, responsiva) ------------------

_PAGE = r"""<!doctype html>
<html lang="pt-br"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PermiScan</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--mut:#8b949e;--acc:#58a6ff;
--crit:#f85149;--high:#db6d28;--med:#d29922;--low:#58a6ff;--info:#8b949e;--ok:#3fb950}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif}
a{color:var(--acc);text-decoration:none}
header{padding:16px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center}
header b{font-size:18px}header .mut{color:var(--mut)}
main{max-width:1100px;margin:0 auto;padding:16px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.card h3{margin:0 0 4px;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}
.card .big{font-size:28px;font-weight:700}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:14px 0}
input,select,textarea,button{font:inherit;background:var(--bg);color:var(--fg);
border:1px solid var(--line);border-radius:8px;padding:8px 10px}
button{cursor:pointer;background:var(--panel)}button:hover{border-color:var(--acc)}
button.pri{background:var(--acc);color:#0d1117;border-color:var(--acc);font-weight:600}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr.clk{cursor:pointer}tr.clk:hover td{background:#1c2330}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.s-critical{background:#3d1416;color:var(--crit)}.s-high{background:#3a2412;color:var(--high)}
.s-medium{background:#3a3212;color:var(--med)}.s-low{background:#12243a;color:var(--low)}
.s-info{background:#21262d;color:var(--info)}
.tag{background:#21262d;color:var(--mut);padding:1px 8px;border-radius:999px;font-size:12px}
.find{border:1px solid var(--line);border-radius:10px;padding:12px;margin:10px 0}
.find.sev-critical{border-left:3px solid var(--crit)}.find.sev-high{border-left:3px solid var(--high)}
.find.sev-medium{border-left:3px solid var(--med)}.find.sev-low{border-left:3px solid var(--low)}
.find.sev-info{border-left:3px solid var(--info)}
.find h4{margin:0 0 4px}.find .desc{color:#c9d1d9;margin:6px 0}
pre{background:#0b0f14;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;
white-space:pre-wrap;word-break:break-all;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;color:#c9d1d9}
.mut{color:var(--mut)}.hide{display:none}.right{margin-left:auto}
.hist li{color:var(--mut);font-size:13px}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0}
.chip{background:#21262d;border:1px solid var(--line);color:var(--fg);border-radius:999px;
  padding:5px 12px;font-size:13px;cursor:pointer}
.chip:hover{border-color:var(--acc)}.chip.on{background:var(--acc);color:#0d1117;border-color:var(--acc);font-weight:600}
.chip.folder::before{content:"📁 "}.chip.sugg{opacity:.6;border-style:dashed}
.crumbs{display:flex;gap:4px;flex-wrap:wrap;align-items:center;margin:6px 0;font-size:13px}
.crumbs a{color:var(--acc)}.crumbs span{color:var(--mut)}
.tblwrap{overflow:auto;max-height:55vh;border:1px solid var(--line);border-radius:8px;margin-top:8px}
.tblwrap table{margin-top:0}.tblwrap th{position:sticky;top:0;background:var(--panel)}
.bar{height:6px;background:#21262d;border-radius:4px;overflow:hidden;margin:6px 0}
.bar i{display:block;height:100%;background:var(--acc)}
@media(max-width:560px){th:nth-child(3),td:nth-child(3){display:none}}
</style></head>
<body>
<header><b>PermiScan</b><span class="mut">plataforma de exploração BaaS · local</span>
<button class="right" onclick="route()">↻</button></header>
<main id="app"></main>
<script>
const $=(h)=>{const d=document.createElement('div');d.innerHTML=h.trim();return d.firstChild}
const api=(p,m,b)=>fetch(p,{method:m||'GET',headers:{'Content-Type':'application/json'},
  body:b?JSON.stringify(b):undefined}).then(r=>r.json())
const esc=(s)=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))
const sev=(s)=>`<span class="pill s-${s}">${s}</span>`
const fmtTs=(iso)=>iso?iso.slice(0,16).replace('T',' '):'—'
const STATUS=["identificado","vuln_confirmado","parcialmente_exploravel","exploracao_validada","corrigido","arquivado"]

async function pollMassScan(jobId,onMsg){
  while(true){
    const j=await api('/api/scan/mass/'+jobId)
    if(j.error){onMsg('erro: '+j.error,true);return}
    onMsg(`${j.done}/${j.total} site(s) · ${j.found} com recursos`,j.finished,j.done/Math.max(1,j.total))
    if(j.finished)return
    await new Promise(r=>setTimeout(r,1200))
  }
}

async function dashboard(){
  const [st,{targets}]=await Promise.all([api('/api/stats'),api('/api/targets')])
  const app=document.getElementById('app');app.innerHTML=''
  app.append($(`<div class="grid">
    <div class="card"><h3>Alvos</h3><div class="big">${st.targets}</div></div>
    <div class="card"><h3>Vuln. confirmadas</h3><div class="big" style="color:var(--crit)">${st.confirmed_targets}</div></div>
    <div class="card"><h3>Findings</h3><div class="big">${st.findings}</div></div>
    <div class="card"><h3>Plataformas</h3><div>${Object.entries(st.by_platform).map(([k,v])=>`<span class="tag">${k}: ${v}</span>`).join(' ')||'—'}</div></div>
  </div>`))

  // --- Novo scan, tudo pela web (sem CLI) ---
  const scanCard=$(`<div class="card" style="margin-top:12px">
    <h3>Novo scan</h3>
    <div class="row">
      <input id="su" placeholder="https://alvo.com" style="flex:1;min-width:200px">
      <select id="sl" title="nível"><option value="1">nível 1 · mínimo</option><option value="2" selected>nível 2 · médio</option><option value="3">nível 3 · máximo</option></select>
      <button class="pri" id="sgo">scanear</button>
      <button id="smass">scan em massa…</button>
    </div>
    <textarea id="smurls" class="hide" placeholder="uma URL por linha" style="width:100%;min-height:70px;margin-top:8px"></textarea>
    <div class="row hide" id="smrow"><button class="pri" id="smgo">rodar scan em massa</button></div>
    <div id="smsg" class="mut" style="margin-top:6px"></div>
    <div class="bar hide" id="sbar"><i style="width:0%"></i></div>
  </div>`)
  app.append(scanCard)
  const smsg=scanCard.querySelector('#smsg'),sbar=scanCard.querySelector('#sbar')
  scanCard.querySelector('#smass').onclick=()=>{
    scanCard.querySelector('#smurls').classList.toggle('hide')
    scanCard.querySelector('#smrow').classList.toggle('hide')
  }
  scanCard.querySelector('#sgo').onclick=async(e)=>{
    const url=scanCard.querySelector('#su').value.trim()
    if(!url)return
    e.target.disabled=true;smsg.textContent='scaneando…'
    const res=await api('/api/scan','POST',{url,level:+scanCard.querySelector('#sl').value})
    e.target.disabled=false
    smsg.textContent=res.error?('erro: '+res.error):`ok · ${res.findings} finding(s)`
    if(!res.error)dashboard()
  }
  scanCard.querySelector('#smgo').onclick=async(e)=>{
    const urls=scanCard.querySelector('#smurls').value.split(/[\n,]/).map(s=>s.trim()).filter(Boolean)
    if(!urls.length)return
    e.target.disabled=true;sbar.classList.remove('hide');sbar.querySelector('i').style.width='0%'
    const res=await api('/api/scan/mass','POST',{urls,level:+scanCard.querySelector('#sl').value})
    if(res.error){smsg.textContent='erro: '+res.error;e.target.disabled=false;return}
    await pollMassScan(res.job_id,(txt,done,frac)=>{
      smsg.textContent=txt;sbar.querySelector('i').style.width=(100*(frac||0))+'%'
      if(done){e.target.disabled=false;sbar.classList.add('hide');dashboard()}
    })
  }

  const bar=$(`<div class="row"><input id="q" placeholder="filtrar por url/ref…" style="flex:1;min-width:160px">
    <select id="fp"><option value="">plataforma</option><option>supabase</option><option>firebase</option><option>site</option></select>
    <select id="fs"><option value="">status</option>${STATUS.map(s=>`<option>${s}</option>`).join('')}</select>
    <label class="mut"><input type="checkbox" id="fc"> só crít./alto</label>
    <select id="so"><option value="recent">mais recentes</option><option value="findings">mais findings</option><option value="sev">mais graves</option></select></div>`)
  app.append(bar)
  const wrap=$('<div></div>');app.append(wrap)
  const draw=()=>{
    const q=(document.getElementById('q').value||'').toLowerCase()
    const fp=document.getElementById('fp').value,fs=document.getElementById('fs').value
    const fc=document.getElementById('fc').checked,so=document.getElementById('so').value
    let rows=targets.filter(t=>(!fp||t.platform==fp)&&(!fs||t.status==fs)&&(!fc||t.crit||t.high)&&
      (!q||(t.url||'').toLowerCase().includes(q)||(t.project_ref||'').toLowerCase().includes(q)))
    rows=[...rows].sort((a,b)=>so==='findings'?b.findings-a.findings:
      so==='sev'?((b.crit||0)*10+(b.high||0))-((a.crit||0)*10+(a.high||0)):
      (b.last_seen||'').localeCompare(a.last_seen||''))
    wrap.innerHTML=rows.length?`<div class="tblwrap"><table><thead><tr><th>alvo</th><th>plataforma</th><th>status</th><th>crít/alto</th><th>findings</th><th>visto</th></tr></thead><tbody>
      ${rows.map(t=>`<tr class="clk" onclick="location.hash='#/t/${t.id}'">
        <td><b>${esc(t.project_ref||t.url)}</b><br><span class="mut">${esc(t.url||'')}</span></td>
        <td><span class="tag">${t.platform}</span></td><td>${esc(t.status)}</td>
        <td>${t.crit?`<span class="pill s-critical">${t.crit}</span> `:''}${t.high?`<span class="pill s-high">${t.high}</span>`:''}</td>
        <td>${t.findings}</td><td class="mut">${fmtTs(t.last_seen)}</td></tr>`).join('')}
      </tbody></table></div>`:'<p class="mut">Nenhum alvo ainda. Rode um scan acima para popular.</p>'
  }
  draw();bar.querySelectorAll('input,select').forEach(e=>e.oninput=draw)
}

const rowsTable=(rows)=>{
  if(!rows||!rows.length)return '<p class="mut">0 registros.</p>'
  const cols=[...new Set(rows.flatMap(r=>Object.keys(r)))].slice(0,14)
  const cell=(v)=>esc(v&&typeof v==='object'?JSON.stringify(v):v)
  return `<div class="tblwrap"><table><thead><tr>${cols.map(c=>`<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>
    ${rows.map(r=>`<tr>${cols.map(c=>`<td>${cell(r[c])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`
}

const filesTable=(files)=>{
  if(!files.length)return '<p class="mut">pasta vazia.</p>'
  return `<div class="tblwrap"><table><thead><tr><th>arquivo</th><th>tamanho</th><th>tipo</th><th>atualizado</th><th></th></tr></thead><tbody>
    ${files.map(f=>`<tr><td>${esc(f.name)}</td><td>${esc(f.size)}</td><td>${esc(f.contentType)}</td>
      <td>${esc(fmtTs(f.updated))}</td><td><a href="${esc(f.url)}" target="_blank" rel="noopener">abrir</a></td></tr>`).join('')}
    </tbody></table></div>`
}

async function workspace(id){
  const t=await api('/api/targets/'+id)
  const app=document.getElementById('app');app.innerHTML=''
  if(t.error){app.innerHTML=`<p>${esc(t.error)}</p><a href="#/">← voltar</a>`;return}
  app.append($(`<div class="row"><a href="#/">← alvos</a>
    <span class="right mut">visto ${esc((t.last_seen||'').slice(0,19).replace('T',' '))}</span></div>`))
  app.append($(`<div class="card"><div class="row" style="margin:0">
    <div><h3>${esc(t.platform)} · ${esc(t.project_ref||'')}</h3>
    <div><a href="${esc(t.url||'#')}" target="_blank" rel="noopener">${esc(t.url||'')}</a></div>
    ${t.api_key?`<div class="mut">chave: ${esc(t.api_key.slice(0,18))}…</div>`:'<div class="mut">sem chave pública armazenada</div>'}</div>
    <div class="right"><button class="pri" id="rescan">re-scan (read-only)</button></div></div>
    <div class="row" style="margin:10px 0 0"><label class="mut">status</label>
      <select id="status">${STATUS.map(s=>`<option ${s==t.status?'selected':''}>${s}</option>`).join('')}</select>
      <button id="save">salvar</button><span id="msg" class="mut"></span></div></div>`))

  const tabs=["Evidências","Explorar","Testes de autorização","Relatório"]
  const bar=$(`<div class="row" style="margin:16px 0 4px">${tabs.map((n,i)=>`<button class="tab" data-i="${i}">${n}</button>`).join('')}</div>`)
  app.append(bar);const pane=$('<div></div>');app.append(pane)

  const msg=document.getElementById('msg')
  document.getElementById('save').onclick=async()=>{
    msg.textContent='salvando…'
    await api('/api/targets/'+id,'POST',{status:document.getElementById('status').value,notes:document.getElementById('notes').value})
    msg.textContent='salvo ✓';setTimeout(()=>msg.textContent='',1500)
  }
  document.getElementById('rescan').onclick=async(e)=>{
    e.target.disabled=true;e.target.textContent='re-scanning…'
    const res=await api('/api/targets/'+id+'/rescan','POST')
    if(res.error)msg.textContent='erro: '+res.error
    workspace(id)
  }

  function paneEvidencias(){
    pane.innerHTML=`<h3 class="mut">Findings & evidências (${t.findings.length})</h3>`
    t.findings.forEach(f=>{
      const ev=f.evidence&&Object.keys(f.evidence).length?`<div class="mut" style="margin-top:6px">evidência</div><pre>${esc(JSON.stringify(f.evidence,null,2))}</pre>`:''
      const poc=f.poc?`<div class="mut" style="margin-top:6px">PoC reproduzível</div><pre>${esc(f.poc)}</pre>`:''
      pane.append($(`<div class="find sev-${f.severity}">
        <div class="row" style="margin:0"><h4>${esc(f.title)}</h4><span class="right">${sev(f.severity)} <span class="tag">${esc(f.confidence)}</span></span></div>
        <div class="mut">${esc(f.rule_id)} · ${esc(f.resource)} ${f.cwe?'· '+esc(f.cwe):''}</div>
        <div class="desc">${esc(f.description)}</div>${ev}${poc}
        ${f.remediation?`<div class="mut" style="margin-top:6px">remediação</div><div class="desc">${esc(f.remediation.summary)}</div>`:''}</div>`))
    })
    pane.append($(`<div class="card" style="margin-top:14px"><h3>Histórico</h3>
      <ul class="hist">${t.activity.map(a=>`<li>${esc(a.ts.slice(0,19).replace('T',' '))} · ${esc(a.kind)} — ${esc(a.detail||'')}</li>`).join('')||'<li>—</li>'}</ul></div>`))
    pane.append($(`<div class="card" style="margin-top:14px"><h3>Anotações</h3>
      <textarea id="notes" style="width:100%;min-height:80px">${esc(t.notes||'')}</textarea></div>`))
  }

  async function paneExplorar(){
    pane.innerHTML='<p class="mut">carregando recursos…</p>'
    const r=await api('/api/targets/'+id+'/resources')
    if(r.error){pane.innerHTML=`<p class="mut">${esc(r.error)}</p>`;return}
    pane.innerHTML=''

    if(r.kind==='supabase'){
      const out=$('<div style="margin-top:8px"></div>')
      const chips=$(`<div class="chips">${r.tables.map(t=>`<span class="chip" data-t="${esc(t)}">${esc(t)}</span>`).join('')}</div>`)
      pane.append($(`<div class="card"><h3>Tabelas <span class="mut" style="font-weight:400">· clique para navegar</span></h3></div>`))
      pane.lastChild.append(chips)
      pane.append($(`<div class="card" style="margin-top:10px">
        <div class="row"><select id="tbl" style="flex:1">${r.tables.map(x=>`<option>${esc(x)}</option>`).join('')}</select>
        <input id="sel" value="*" title="colunas (select)" style="width:110px">
        <input id="ord" placeholder="order (ex: id.desc)" style="width:140px">
        <input id="lim" type="number" value="50" style="width:70px"><input id="off" type="number" value="0" style="width:70px"></div>
        <div class="row"><input id="fc" placeholder="coluna (opcional)"><select id="fo">${["eq","neq","gt","gte","lt","lte","like","ilike","is","in"].map(o=>`<option>${o}</option>`).join('')}</select>
        <input id="fv" placeholder="valor"><button class="pri" id="go">consultar</button></div>
        ${r.rpcs.length?`<div class="mut" style="margin-top:8px">RPCs expostas (chame só na aba "Testes de autorização"): ${
          r.rpcs.map(x=>`<span class="tag">${esc(x.name)} · ${esc(x.risk)}</span>`).join(' ')}</div>`:''}</div>`))
      pane.append(out)
      const run=async()=>{
        out.innerHTML='<p class="mut">consultando…</p>'
        const fc=document.getElementById('fc').value
        const filters=fc?[{col:fc,op:document.getElementById('fo').value,val:document.getElementById('fv').value}]:[]
        const res=await api('/api/targets/'+id+'/rows','POST',{type:'supabase_table',resource:document.getElementById('tbl').value,
          select:document.getElementById('sel').value,order:document.getElementById('ord').value||null,
          limit:+document.getElementById('lim').value,offset:+document.getElementById('off').value,filters})
        out.innerHTML=res.error?`<p class="mut">erro: ${esc(res.error)}</p>`:
          `<div class="mut">${res.count!=null?res.count+' no total':''}</div>`+rowsTable(res.rows)
      }
      chips.querySelectorAll('.chip').forEach(c=>c.onclick=()=>{
        chips.querySelectorAll('.chip').forEach(x=>x.classList.remove('on'));c.classList.add('on')
        document.getElementById('tbl').value=c.dataset.t;document.getElementById('fc').value='';run()
      })
      document.getElementById('go').onclick=run
      document.getElementById('tbl').onchange=run
      if(chips.firstChild)chips.firstChild.classList.add('on')
      run()  // primeira tabela já carrega sozinha — nada pra digitar
      return
    }

    if(r.kind!=='firebase'){pane.innerHTML='<p class="mut">Este alvo não tem recurso explorável (sem chave pública salva).</p>';return}
    if(!r.collections.length && !r.rtdb && !r.bucket){
      pane.innerHTML='<p class="mut">Nenhuma coleção, RTDB ou bucket confirmados como públicos neste alvo ainda.</p>';return
    }

    // --- Firestore: coleções confirmadas primeiro (sólidas), sugestões por nome comum depois ---
    const allCols=[...r.collections.map(c=>({name:c,sugg:false})),...r.collections_suggested.map(c=>({name:c,sugg:true}))]
    if(allCols.length){
      const outFs=$('<div style="margin-top:8px"></div>')
      const chips=$(`<div class="chips">${allCols.map(c=>`<span class="chip${c.sugg?' sugg':''}" data-c="${esc(c.name)}" title="${c.sugg?'não confirmada — tentativa':'confirmada no scan'}">${esc(c.name)}</span>`).join('')}</div>`)
      pane.append($(`<div class="card"><h3>Firestore</h3><div class="mut">clique numa coleção para ler os documentos ${r.collections.length?'':'(nenhuma confirmada — tentando nomes comuns)'}</div></div>`))
      pane.lastChild.append(chips);pane.append(outFs)
      const loadCol=(name)=>{
        chips.querySelectorAll('.chip').forEach(x=>x.classList.toggle('on',x.dataset.c===name))
        outFs.innerHTML='<p class="mut">carregando…</p>'
        api('/api/targets/'+id+'/rows','POST',{type:'firestore',resource:name}).then(res=>{
          outFs.innerHTML=res.error?`<p class="mut">erro: ${esc(res.error)}</p>`:`<div class="mut">${res.count} documento(s)</div>`+rowsTable(res.rows)
        })
      }
      chips.querySelectorAll('.chip').forEach(c=>c.onclick=()=>loadCol(c.dataset.c))
      loadCol(allCols[0].name)  // auto-abre a primeira
    }

    // --- Realtime Database: navega por chaves (shallow), sem precisar digitar caminho ---
    if(r.rtdb){
      let path=[]
      const outRt=$('<div style="margin-top:8px"></div>')
      pane.append($(`<div class="card" style="margin-top:10px"><h3>Realtime Database</h3></div>`))
      pane.lastChild.append(outRt)
      const loadRt=async()=>{
        outRt.innerHTML='<p class="mut">carregando…</p>'
        const res=await api('/api/targets/'+id+'/rows','POST',{type:'rtdb',path:path.join('/'),shallow:true})
        if(res.error){outRt.innerHTML=`<p class="mut">erro: ${esc(res.error)}</p>`;return}
        const crumbs=`<div class="crumbs"><a data-i="-1">raiz</a>${path.map((p,i)=>` / <a data-i="${i}">${esc(p)}</a>`).join('')}</div>`
        const data=res.data,keys=data&&typeof data==='object'?Object.keys(data):null
        const body=keys?(keys.length?`<div class="chips">${keys.map(k=>`<span class="chip folder" data-k="${esc(k)}">${esc(k)}</span>`).join('')}</div>`:'<p class="mut">nó vazio.</p>')
          :`<pre>${esc(JSON.stringify(data))}</pre>`
        outRt.innerHTML=crumbs+body
        outRt.querySelectorAll('.crumbs a').forEach(a=>a.onclick=()=>{path=path.slice(0,+a.dataset.i+1);loadRt()})
        outRt.querySelectorAll('.chip').forEach(c=>c.onclick=()=>{path=[...path,c.dataset.k];loadRt()})
      }
      loadRt()  // raiz carrega sozinha
    }

    // --- Storage: pastas (prefixes) e arquivos navegáveis, sem digitar prefixo ---
    if(r.bucket){
      let prefix=''
      const outSt=$('<div style="margin-top:8px"></div>')
      pane.append($(`<div class="card" style="margin-top:10px"><h3>Storage · ${esc(r.bucket)}</h3></div>`))
      pane.lastChild.append(outSt)
      const loadSt=async()=>{
        outSt.innerHTML='<p class="mut">carregando…</p>'
        const res=await api('/api/targets/'+id+'/rows','POST',{type:'storage',prefix,bucket:r.bucket})
        if(res.error){outSt.innerHTML=`<p class="mut">erro: ${esc(res.error)}</p>`;return}
        const segs=prefix?prefix.split('/'):[]
        const crumbs=`<div class="crumbs"><a data-p="">raiz</a>${segs.map((s,i)=>` / <a data-p="${esc(segs.slice(0,i+1).join('/'))}">${esc(s)}</a>`).join('')}</div>`
        const folders=res.prefixes.length?`<div class="chips">${res.prefixes.map(p=>`<span class="chip folder" data-p="${esc(p)}">${esc(p.split('/').pop())}</span>`).join('')}</div>`:''
        outSt.innerHTML=crumbs+folders+filesTable(res.rows)
        outSt.querySelectorAll('.crumbs a').forEach(a=>a.onclick=()=>{prefix=a.dataset.p;loadSt()})
        outSt.querySelectorAll('.chip.folder').forEach(c=>c.onclick=()=>{prefix=c.dataset.p;loadSt()})
      }
      loadSt()  // raiz do bucket carrega sozinha
    }
  }

  async function paneAuthz(){
    if(t.platform!=='supabase'){pane.innerHTML='<p class="mut">Testes de autorização disponíveis para alvos Supabase.</p>';return}
    pane.innerHTML='<p class="mut">carregando tabelas…</p>'
    const r=await api('/api/targets/'+id+'/resources')
    if(r.error||r.kind!=='supabase'){pane.innerHTML=`<p class="mut">${esc(r.error||'indisponível')}</p>`;return}
    pane.innerHTML=''
    pane.append($(`<div class="card"><div class="mut">Selecione a tabela. Estes testes agem sobre o alvo; use só onde você tem autorização.</div>
      <div class="row"><select id="atbl">${r.tables.map(x=>`<option>${esc(x)}</option>`).join('')}</select></div>
      <div class="row"><label><input type="checkbox" id="allow"> permitir ESCRITA de teste (POST vazio)</label><button id="w">testar escrita</button></div>
      <div class="row"><label><input type="checkbox" id="mkuser"> criar usuário sintético (cria conta no alvo)</label><button id="d">comparar identidades (RLS)</button></div>
    </div>`))
    const o=$('<div style="margin-top:12px"></div>');pane.append(o)
    document.getElementById('w').onclick=async()=>{o.innerHTML='…'
      const res=await api('/api/targets/'+id+'/authz','POST',{mode:'write',resource:document.getElementById('atbl').value,allow_write:document.getElementById('allow').checked})
      o.innerHTML=res.error?`<p class="mut">${esc(res.error)}</p>`:`<pre>${esc(JSON.stringify(res,null,2))}</pre>`}
    document.getElementById('d').onclick=async()=>{o.innerHTML='…'
      const res=await api('/api/targets/'+id+'/authz','POST',{mode:'diff',resource:document.getElementById('atbl').value,create_test_user:document.getElementById('mkuser').checked})
      o.innerHTML=res.error?`<p class="mut">${esc(res.error)}</p>`:`<pre>${esc(JSON.stringify(res,null,2))}</pre>`}
  }

  function paneRelatorio(){
    pane.innerHTML=`<div class="card"><h3>Relatório técnico</h3>
      <p class="mut">Evidências e PoCs deste alvo, prontos para compartilhar.</p>
      <div class="row"><a class="tag" style="padding:8px 12px" href="/api/targets/${id}/report.html" target="_blank">abrir HTML (imprima p/ PDF)</a>
      <a class="tag" style="padding:8px 12px" href="/api/targets/${id}/report.json" target="_blank">baixar JSON</a></div></div>`
  }

  const panes=[paneEvidencias,paneExplorar,paneAuthz,paneRelatorio]
  bar.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{
    bar.querySelectorAll('.tab').forEach(x=>x.classList.remove('pri'))
    b.classList.add('pri');panes[+b.dataset.i]()
  })
  bar.querySelector('.tab').click()
}

function route(){
  const m=location.hash.match(/^#\/t\/(\d+)/)
  if(m)workspace(+m[1]);else dashboard()
}
addEventListener('hashchange',route);route()
</script></body></html>"""
