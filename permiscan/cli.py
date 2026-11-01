import argparse
import json
import os
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from permiscan.adapters import PROVIDERS
from permiscan.adapters.base import AdapterError
from permiscan.adapters.firebase import FirebaseAdapter
from permiscan.adapters.supabase_api import (
    ApiScanOptions,
    SupabaseApiScanner,
    detect_instances,
    fetch_text,
)
from permiscan.audit import (
    load_instances_from_batch_json,
    load_instances_from_file,
    print_audit_report,
    save_audit_json,
    audit_supabase_instances,
)
from permiscan.batch import (
    load_urls_from_file,
    print_text_report,
    save_csv,
    save_json,
    scan_batch,
)
from permiscan.discovery import Recon, ReconResult, options_for_level
from permiscan.findings import Finding, Severity
from permiscan.scope import ScopeError, authorize, load_scope, parse_dsn
from permiscan import report
from rich.text import Text

EXIT_ERROR, EXIT_SCOPE, EXIT_FAIL_ON = 1, 2, 3


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permiscan",
        description="Auditoria de controle de acesso. Use apenas em alvos que você é dono ou está autorizado a testar.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    report = argparse.ArgumentParser(add_help=False)
    report.add_argument("--format", choices=["text", "json"], default="text")
    report.add_argument("--output", type=Path, help="grava o resultado em arquivo em vez da saída padrão")
    report.add_argument("--fail-on", choices=[s.value for s in Severity],
                        help=f"sai com código {EXIT_FAIL_ON} se houver finding com esta severidade ou maior")

    # Banco de dados (PostgreSQL / Supabase via conexão direta).
    db = argparse.ArgumentParser(add_help=False)
    db.add_argument("--provider", choices=sorted(PROVIDERS), required=True)
    db.add_argument("--scope", type=Path,
                    help="arquivo TOML de alvos autorizados (opcional; o DSN já fixa o alvo)")
    db.add_argument("--dsn-env", default="PERMISCAN_DSN",
                    help="variável de ambiente com o DSN; credenciais nunca vêm por argumento (padrão: %(default)s)")
    db.add_argument("--role", action="append", dest="roles",
                    help="papel a auditar, repetível (supabase: anon e authenticated por padrão)")
    db.add_argument("--schema", action="append", dest="schemas",
                    help="schema a analisar, repetível (supabase: public; postgresql: todos)")
    sub.add_parser("check", parents=[db], help="valida conexão com o banco")
    sub.add_parser("scan", parents=[db, report], help="análise estática do catálogo do banco")

    # Modos de prova ativos da Data API, compartilhados por scan-api e detect --scan.
    probe = argparse.ArgumentParser(add_help=False)
    probe.add_argument("--rows", type=int, default=1, metavar="N",
                       help="linhas lidas por tabela como anônimo (padrão: 1)")
    probe.add_argument("--probe-writes", action="store_true",
                       help="testa escrita anônima (POST); pode inserir uma linha em tabelas graváveis")
    probe.add_argument("--probe-rpc", action="store_true",
                       help="chama funções RPC para ver se respondem sem autenticação")
    probe.add_argument("--include-destructive", action="store_true",
                       help="também chama RPCs de nome destrutivo (delete/drop/admin/…)")

    # Varredura externa pela Data API do Supabase (URL + chave anon, ambas públicas).
    api = sub.add_parser("scan-api", parents=[report, probe],
                         help="varredura externa de um projeto Supabase pela Data API")
    api.add_argument("--url", required=True, help="URL do projeto, ex.: https://xxxx.supabase.co")
    api.add_argument("--key-env", default="PERMISCAN_ANON_KEY",
                     help="variável de ambiente com a chave anon (padrão: %(default)s)")

    # Detecção de credenciais em uma página ou bundle (recon da extensão).
    det = sub.add_parser("detect", parents=[report, probe],
                         help="extrai URL/chaves Supabase de uma página ou arquivo; com --scan, varre")
    src = det.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="busca uma página e procura credenciais nela")
    src.add_argument("--file", type=Path, help="procura credenciais em um arquivo local (HTML, JS, .env)")
    det.add_argument("--scan", action="store_true", help="varre cada instância detectada pela Data API")

    # Reconhecimento automático: identifica a stack, descobre endpoints e roteia.
    rec = sub.add_parser("recon", parents=[report, probe],
                         help="dado só uma URL, identifica a stack e roda as análises cabíveis")
    rec.add_argument("url", help="URL do alvo, ex.: https://app.exemplo.com")
    rec.add_argument("--level", type=int, choices=[1, 2, 3], default=2,
                     help="1=mínimo (identifica), 2=médio (enumera/lê), 3=máximo (extrai/ativo)")

    # Processamento em massa de sites.
    batch = sub.add_parser("batch", parents=[report, probe],
                           help="processa uma lista de sites em massa")
    src = batch.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", type=Path, help="arquivo com URLs (uma por linha)")
    src.add_argument("--urls", nargs="+", help="lista de URLs como argumentos")
    batch.add_argument("--workers", type=int, default=10, 
                       help="número de workers paralelos (padrão: %(default)s)")
    batch.add_argument("--output-json", type=Path, help="salva resultados em JSON")
    batch.add_argument("--output-csv", type=Path, help="salva resumo em CSV")

    # Auditoria automática de instâncias Supabase.
    audit = sub.add_parser("audit", parents=[report],
                           help="auditoria automática de instâncias Supabase (extrai chaves e testa RLS)")
    src_audit = audit.add_mutually_exclusive_group(required=True)
    src_audit.add_argument("--from-batch", type=Path, 
                          help="JSON do comando batch para extrair instâncias automaticamente")
    src_audit.add_argument("--file", type=Path, 
                          help="arquivo com URLs Supabase (uma por linha)")
    src_audit.add_argument("--urls", nargs="+", help="lista de URLs Supabase como argumentos")
    audit.add_argument("--workers", type=int, default=10,
                       help="número de workers paralelos (padrão: %(default)s)")
    audit.add_argument("--no-writes", action="store_true",
                       help="não testar escrita (apenas leitura)")
    audit.add_argument("--no-rpc", action="store_true",
                       help="não testar funções RPC")
    audit.add_argument("--output-json", type=Path, help="salva resultados em JSON")

    # Firebase Security Rules (arquivo local).
    rules = sub.add_parser("scan-rules", parents=[report],
                           help="análise estática de Firebase Security Rules")
    rules.add_argument("--rules", type=Path, required=True, help="caminho do arquivo de regras")
    rules.add_argument("--service", choices=["firestore", "storage", "database", "rtdb"],
                       help="serviço das regras (detectado pelo nome do arquivo se omitido)")
    return parser


def _db_warnings(info: dict) -> list[str]:
    out = []
    if info["connected_as_superuser"]:
        out.append(f"conectado como superusuário ({info['connected_as']}); prefira um papel somente leitura dedicado")
    if not info["read_only"]:
        out.append("a sessão não está em modo somente leitura")
    if info["missing_roles"]:
        out.append(f"papéis inexistentes no alvo: {', '.join(info['missing_roles'])}")
    if info["missing_schemas"]:
        out.append(f"schemas inexistentes no alvo: {', '.join(info['missing_schemas'])}")
    return out


def _emit(info: dict, findings: list[Finding], started: datetime, finished: datetime, args) -> int:
    if args.format == "json":
        output = json.dumps({
            "provider": info["provider"],
            "target": info["target"],
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "summary": dict(Counter(f.severity.value for f in findings)),
            "findings": [f.model_dump(mode="json") for f in findings],
        }, indent=2, ensure_ascii=False)
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output)
    else:
        group = report.findings_group(f"PermiScan · {info['provider']} @ {info['target']}", findings)
        report.render(group, args.output)

    if args.fail_on and any(f.severity.rank <= Severity(args.fail_on).rank for f in findings):
        return EXIT_FAIL_ON
    return 0


def _emit_recon(result: ReconResult, args) -> int:
    if args.format == "json":
        output = json.dumps({
            "target": result.target,
            "stacks": [{"name": s.name, "confidence": s.confidence, "evidence": s.evidence} for s in result.stacks],
            "firebase_config": dict(result.firebase_config),  # config web do Firebase é público por design (apiKey inclusa)
            "supabase_instances": [{"url": i.url, "keys": [k["role"] for k in i.keys]} for i in result.supabase_instances],
            "endpoints": [{"path": e.path, "status": e.status, "content_type": e.content_type} for e in result.endpoints],
            "summary": dict(Counter(f.severity.value for f in result.findings)),
            "findings": [f.model_dump(mode="json") for f in result.findings],
            "recommendations": result.recommendations,
        }, indent=2, ensure_ascii=False)
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output)
    else:
        rows = []
        stacks = ", ".join(f"{s.name} ({s.confidence})" for s in result.stacks) or "não identificada"
        rows.append(("stack", stacks))
        if result.firebase_config:
            rows.append(("firebase", ", ".join(
                f"{k}={v}" for k, v in result.firebase_config.items())))
        for inst in result.supabase_instances:
            rows.append(("supabase", f"{inst.url}  (chaves: {', '.join(k['role'] for k in inst.keys) or 'nenhuma'})"))
        extra = [report.kv_table(rows)]
        if result.endpoints:
            extra += [Text("Endpoints descobertos:", style="bold"), report.endpoints_table(result.endpoints)]
        if result.recommendations:
            extra += [Text("Recomendações:", style="bold"),
                      *[Text(f"  • {r}", style="grey70") for r in result.recommendations]]
        group = report.findings_group(f"PermiScan recon · {result.target}", result.findings, extra)
        report.render(group, args.output)

    if args.fail_on and any(f.severity.rank <= Severity(args.fail_on).rank for f in result.findings):
        return EXIT_FAIL_ON
    return 0


def _options(args) -> ApiScanOptions:
    return ApiScanOptions(
        rows=max(1, args.rows), probe_writes=args.probe_writes,
        probe_rpc=args.probe_rpc, include_destructive=args.include_destructive,
    )


def _probe_warnings(opt: ApiScanOptions) -> None:
    if opt.probe_writes:
        print("aviso: --probe-writes pode inserir linhas em tabelas graváveis pelo anon", file=sys.stderr)
    if opt.include_destructive:
        print("aviso: --include-destructive chama RPCs de nome destrutivo; use só em alvo próprio/de teste",
              file=sys.stderr)


def _detect(args) -> tuple[dict, list[Finding]]:
    if args.url:
        # Similar ao recon: baixa HTML + scripts JS para encontrar chaves
        text = fetch_text(args.url)
        # Extrai scripts JS para buscar chaves (igual ao recon)
        from permiscan.discovery import script_srcs
        for src in script_srcs(text, args.url):
            try:
                text += "\n" + fetch_text(src)
            except AdapterError:
                continue
    else:
        text = _read_file(args.file)
    
    source = args.url or str(args.file)
    instances = detect_instances(text)
    if not instances:
        print(f"nenhuma instância Supabase encontrada em {source}", file=sys.stderr)
        return {"provider": "supabase-api", "target": source}, []

    for inst in instances:
        print(f"detectado: {inst.url}", file=sys.stderr)
        for k in inst.keys:
            flag = "  <<< service_role (crítico se veio do cliente)" if k["role"] == "service_role" else ""
            print(f"  chave {k['role']} (ref={k['ref']}): {k['key'][:24]}…{flag}", file=sys.stderr)

    if not args.scan:
        return {"provider": "supabase-api", "target": source}, []

    opt = _options(args)
    _probe_warnings(opt)
    findings: list[Finding] = []
    for inst in instances:
        if not inst.anon_key:
            print(f"aviso: {inst.url} sem chave utilizável; pulando varredura", file=sys.stderr)
            continue
        findings += SupabaseApiScanner(inst.url, inst.anon_key, opt).scan()
    return {"provider": "supabase-api", "target": source}, findings


def _read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise AdapterError(f"não foi possível ler {path}: {e}") from None


def _build_db_adapter(args):
    dsn = os.environ.get(args.dsn_env)
    if not dsn:
        raise AdapterError(f"defina a variável de ambiente {args.dsn_env} com o DSN do alvo")
    target = parse_dsn(dsn)
    if args.scope:  # opcional; quando presente, o alvo precisa constar da allowlist
        authorize(target, load_scope(args.scope))
    return PROVIDERS[args.provider](target, roles=args.roles, schemas=args.schemas)


def dispatch(args) -> int:
    try:
        if args.command in ("check", "scan"):
            adapter = _build_db_adapter(args)
            info = adapter.check()
            for w in _db_warnings(info):
                print(f"aviso: {w}", file=sys.stderr)
            if args.command == "check":
                print(json.dumps(info, indent=2, ensure_ascii=False))
                return 0
        elif args.command == "recon":
            opt = options_for_level(args.level)
            # flags explícitas podem escalar além do nível
            opt.probe_writes |= args.probe_writes
            opt.probe_rpc |= args.probe_rpc
            opt.include_destructive |= args.include_destructive
            _probe_warnings(opt)
            return _emit_recon(Recon(args.url, opt, level=args.level).run(), args)
        elif args.command == "batch":
            opt = _options(args)
            _probe_warnings(opt)
            
            # Carrega URLs
            if args.file:
                urls = load_urls_from_file(args.file)
                print(f"Carregadas {len(urls)} URLs de {args.file}", file=sys.stderr)
            else:
                urls = args.urls
            
            if not urls:
                raise AdapterError("nenhuma URL fornecida")
            
            # Callback de progresso
            def progress(completed, total, result):
                status = "[OK]" if result.success else "[X]"
                print(f"[{completed}/{total}] {status} {result.url} ({result.scan_time:.2f}s)", file=sys.stderr)
            
            print(f"Iniciando scan de {len(urls)} sites com {args.workers} workers...", file=sys.stderr)
            results, summary = scan_batch(urls, opt, args.workers, progress)
            
            # Salva arquivos se solicitado
            if args.output_json:
                save_json(results, summary, args.output_json)
                print(f"JSON salvo em {args.output_json}", file=sys.stderr)
            if args.output_csv:
                save_csv(results, summary, args.output_csv)
                print(f"CSV salvo em {args.output_csv}", file=sys.stderr)
            
            # Imprime relatório
            print_text_report(results, summary)
            
            # Sai com erro se houver findings críticos
            if summary.critical_findings > 0:
                return EXIT_FAIL_ON
            return 0
        elif args.command == "audit":
            # Configura opções automáticas
            opt = ApiScanOptions(
                rows=1,
                probe_writes=not args.no_writes,
                probe_rpc=not args.no_rpc,
                include_destructive=False,  # Nunca chama destrutivos automaticamente
            )
            
            # Carrega instâncias
            if args.from_batch:
                instances = load_instances_from_batch_json(args.from_batch)
                print(f"Carregadas {len(instances)} instancias do batch JSON", file=sys.stderr)
            elif args.file:
                instances = load_instances_from_file(args.file)
                print(f"Carregadas {len(instances)} URLs de {args.file}", file=sys.stderr)
            else:
                instances = [(url, None) for url in args.urls]
            
            if not instances:
                raise AdapterError("nenhuma instancia fornecida")
            
            # Callback de progresso
            def progress(completed, total, result):
                status = "[OK]" if result.success else "[X]"
                key_status = "[KEY]" if result.key_found else "[NOKEY]"
                print(f"[{completed}/{total}] {status} {key_status} {result.supabase_url} ({result.scan_time:.2f}s)", file=sys.stderr)
            
            print(f"Iniciando auditoria de {len(instances)} instancias com {args.workers} workers...", file=sys.stderr)
            print(f"Modo: probe_writes={opt.probe_writes}, probe_rpc={opt.probe_rpc}", file=sys.stderr)
            results, summary = audit_supabase_instances(instances, opt, args.workers, progress)
            
            # Salva JSON se solicitado
            if args.output_json:
                save_audit_json(results, summary, args.output_json)
                print(f"JSON salvo em {args.output_json}", file=sys.stderr)
            
            # Imprime relatório
            print_audit_report(results, summary)
            
            # Sai com erro se houver findings críticos
            if summary.critical_findings > 0:
                return EXIT_FAIL_ON
            return 0
        elif args.command == "detect":
            started = datetime.now(UTC)
            info, findings = _detect(args)
            finished = datetime.now(UTC)
            return _emit(info, findings, started, finished, args)
        elif args.command == "scan-api":
            key = os.environ.get(args.key_env)
            if not key:
                raise AdapterError(f"defina a variável de ambiente {args.key_env} com a chave anon")
            opt = _options(args)
            _probe_warnings(opt)
            adapter = SupabaseApiScanner(args.url, key, opt)
            info = adapter.check()
        else:  # scan-rules
            adapter = FirebaseAdapter(args.rules, args.service)
            info = adapter.check()

        started = datetime.now(UTC)
        findings = adapter.scan()
        finished = datetime.now(UTC)
    except ScopeError as e:
        print(f"erro de escopo: {e}", file=sys.stderr)
        return EXIT_SCOPE
    except AdapterError as e:
        print(f"erro: {e}", file=sys.stderr)
        return EXIT_ERROR

    return _emit(info, findings, started, finished, args)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:  # sem argumentos: menu interativo
        from permiscan.menu import run_menu
        return run_menu()
    return dispatch(_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
