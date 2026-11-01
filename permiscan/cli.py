import argparse
import json
import os
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from permiscan.adapters import PROVIDERS
from permiscan.adapters.base import AdapterError
from permiscan.findings import Finding, Severity
from permiscan.scope import ScopeError, authorize, load_scope, parse_dsn

EXIT_ERROR, EXIT_SCOPE, EXIT_FAIL_ON = 1, 2, 3


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permiscan",
        description="Auditoria de controle de acesso. Use apenas em alvos que você está autorizado a testar.",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--provider", choices=sorted(PROVIDERS), required=True)
    common.add_argument("--scope", type=Path, default=Path("permiscan-scope.toml"),
                        help="arquivo TOML com os alvos autorizados (padrão: %(default)s)")
    common.add_argument("--dsn-env", default="PERMISCAN_DSN",
                        help="variável de ambiente com o DSN; credenciais nunca são aceitas por argumento (padrão: %(default)s)")
    common.add_argument("--role", action="append", dest="roles",
                        help="papel a auditar, repetível (supabase: anon e authenticated por padrão)")
    common.add_argument("--schema", action="append", dest="schemas",
                        help="schema a analisar, repetível (supabase: public; postgresql: todos)")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", parents=[common], help="valida escopo e conexão")
    scan = sub.add_parser("scan", parents=[common], help="executa a análise estática")
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.add_argument("--output", type=Path, help="grava o resultado em arquivo em vez da saída padrão")
    scan.add_argument("--fail-on", choices=[s.value for s in Severity],
                      help=f"sai com código {EXIT_FAIL_ON} se houver finding com esta severidade ou maior")
    return parser


def _warnings(info: dict) -> list[str]:
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


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    dsn = os.environ.get(args.dsn_env)
    if not dsn:
        print(f"erro: defina a variável de ambiente {args.dsn_env} com o DSN do alvo", file=sys.stderr)
        return EXIT_ERROR

    try:
        target = parse_dsn(dsn)
        authorize(target, load_scope(args.scope))
        adapter = PROVIDERS[args.provider](target, roles=args.roles, schemas=args.schemas)
        info = adapter.check()
        for w in _warnings(info):
            print(f"aviso: {w}", file=sys.stderr)
        if args.command == "check":
            print(json.dumps(info, indent=2, ensure_ascii=False))
            return 0
        started = datetime.now(UTC)
        findings = adapter.scan()
        finished = datetime.now(UTC)
    except ScopeError as e:
        print(f"erro de escopo: {e}", file=sys.stderr)
        return EXIT_SCOPE
    except AdapterError as e:
        print(f"erro: {e}", file=sys.stderr)
        return EXIT_ERROR

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


if __name__ == "__main__":
    sys.exit(main())
