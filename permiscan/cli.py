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
from permiscan.adapters.supabase_api import SupabaseApiScanner
from permiscan.findings import Finding, Severity
from permiscan.scope import ScopeError, authorize, load_scope, parse_dsn

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

    # Varredura externa pela Data API do Supabase (URL + chave anon, ambas públicas).
    api = sub.add_parser("scan-api", parents=[report],
                         help="varredura externa de um projeto Supabase pela Data API")
    api.add_argument("--url", required=True, help="URL do projeto, ex.: https://xxxx.supabase.co")
    api.add_argument("--key-env", default="PERMISCAN_ANON_KEY",
                     help="variável de ambiente com a chave anon (padrão: %(default)s)")

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


def _text_report(info: dict, findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[s]} {s}" for s in Severity if counts[s]) or "nenhum"
    lines = [f"PermiScan · {info['provider']} @ {info['target']}", f"Findings: {len(findings)} ({summary})", ""]
    for f in findings:
        refs = " · ".join(x for x in (f.cwe, f.owasp) if x)
        lines += [
            f"[{f.severity.upper()}] {f.title}",
            f"  recurso:   {f.resource}",
            f"  regra:     {f.rule_id} · confiança: {f.confidence} · {refs}",
            f"  {f.description}",
            f"  correção:  {f.remediation.summary}",
        ]
        if f.remediation.sql:
            lines += ["    " + line for line in f.remediation.sql.splitlines()]
        lines.append("")
    return "\n".join(lines)


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
    else:
        output = _text_report(info, findings)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output)

    if args.fail_on and any(f.severity.rank <= Severity(args.fail_on).rank for f in findings):
        return EXIT_FAIL_ON
    return 0


def _build_db_adapter(args):
    dsn = os.environ.get(args.dsn_env)
    if not dsn:
        raise AdapterError(f"defina a variável de ambiente {args.dsn_env} com o DSN do alvo")
    target = parse_dsn(dsn)
    if args.scope:  # opcional; quando presente, o alvo precisa constar da allowlist
        authorize(target, load_scope(args.scope))
    return PROVIDERS[args.provider](target, roles=args.roles, schemas=args.schemas)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command in ("check", "scan"):
            adapter = _build_db_adapter(args)
            info = adapter.check()
            for w in _db_warnings(info):
                print(f"aviso: {w}", file=sys.stderr)
            if args.command == "check":
                print(json.dumps(info, indent=2, ensure_ascii=False))
                return 0
        elif args.command == "scan-api":
            key = os.environ.get(args.key_env)
            if not key:
                raise AdapterError(f"defina a variável de ambiente {args.key_env} com a chave anon")
            adapter = SupabaseApiScanner(args.url, key)
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


if __name__ == "__main__":
    sys.exit(main())
