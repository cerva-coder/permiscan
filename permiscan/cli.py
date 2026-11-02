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
        description="Access-control audit. Use only on targets you own or are authorized to test.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    report = argparse.ArgumentParser(add_help=False)
    report.add_argument("--format", choices=["text", "json"], default="text")
    report.add_argument("--output", type=Path, help="write the result to a file instead of stdout")
    report.add_argument("--fail-on", choices=[s.value for s in Severity],
                        help=f"exit with code {EXIT_FAIL_ON} if there's a finding at this severity or higher")

    # Database (PostgreSQL / Supabase via direct connection).
    db = argparse.ArgumentParser(add_help=False)
    db.add_argument("--provider", choices=sorted(PROVIDERS), required=True)
    db.add_argument("--scope", type=Path,
                    help="TOML file of authorized targets (optional; the DSN already pins the target)")
    db.add_argument("--dsn-env", default="PERMISCAN_DSN",
                    help="environment variable holding the DSN; credentials never come as an argument (default: %(default)s)")
    db.add_argument("--role", action="append", dest="roles",
                    help="role to audit, repeatable (supabase: anon and authenticated by default)")
    db.add_argument("--schema", action="append", dest="schemas",
                    help="schema to analyze, repeatable (supabase: public; postgresql: all)")
    sub.add_parser("check", parents=[db], help="validates the database connection")
    sub.add_parser("scan", parents=[db, report], help="static analysis of the database catalog")

    # Active probe modes on the Data API, shared by scan-api and detect --scan.
    probe = argparse.ArgumentParser(add_help=False)
    probe.add_argument("--rows", type=int, default=1, metavar="N",
                       help="rows read per table as anonymous (default: 1)")
    probe.add_argument("--probe-writes", action="store_true",
                       help="tests anonymous writes (POST); may insert a row into writable tables")
    probe.add_argument("--probe-rpc", action="store_true",
                       help="calls RPC functions to see if they respond without authentication")
    probe.add_argument("--include-destructive", action="store_true",
                       help="also calls RPCs with a destructive-sounding name (delete/drop/admin/…)")

    # External scan through the Supabase Data API (URL + anon key, both public).
    api = sub.add_parser("scan-api", parents=[report, probe],
                         help="external scan of a Supabase project through the Data API")
    api.add_argument("--url", required=True, help="project URL, e.g. https://xxxx.supabase.co")
    api.add_argument("--key-env", default="PERMISCAN_ANON_KEY",
                     help="environment variable holding the anon key (default: %(default)s)")

    # Credential detection on a page or bundle (the extension's recon).
    det = sub.add_parser("detect", parents=[report, probe],
                         help="extracts Supabase URL/keys from a page or file; scans with --scan")
    src = det.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="fetches a page and looks for credentials in it")
    src.add_argument("--file", type=Path, help="looks for credentials in a local file (HTML, JS, .env)")
    det.add_argument("--scan", action="store_true", help="scans each detected instance through the Data API")

    # Automatic recon: identifies the stack, discovers endpoints, and routes.
    rec = sub.add_parser("recon", parents=[report, probe],
                         help="given just a URL, identifies the stack and runs the fitting analyses")
    rec.add_argument("url", help="target URL, e.g. https://app.example.com")
    rec.add_argument("--level", type=int, choices=[1, 2, 3], default=2,
                     help="1=minimal (identify), 2=medium (enumerate/read), 3=maximum (extract/active)")

    # Mass site processing.
    batch = sub.add_parser("batch", parents=[report, probe],
                           help="processes a list of sites in bulk")
    src = batch.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", type=Path, help="file with URLs (one per line)")
    src.add_argument("--urls", nargs="+", help="list of URLs as arguments")
    batch.add_argument("--workers", type=int, default=10,
                       help="number of parallel workers (default: %(default)s)")
    batch.add_argument("--output-json", type=Path, help="save results to JSON")
    batch.add_argument("--output-csv", type=Path, help="save a summary to CSV")

    # Automatic bulk Supabase auditing.
    audit = sub.add_parser("audit", parents=[report],
                           help="automatic bulk audit of Supabase instances (extracts keys and tests RLS)")
    src_audit = audit.add_mutually_exclusive_group(required=True)
    src_audit.add_argument("--from-batch", type=Path,
                          help="JSON from the batch command, to extract instances automatically")
    src_audit.add_argument("--file", type=Path,
                          help="file with Supabase URLs (one per line)")
    src_audit.add_argument("--urls", nargs="+", help="list of Supabase URLs as arguments")
    audit.add_argument("--workers", type=int, default=10,
                       help="number of parallel workers (default: %(default)s)")
    audit.add_argument("--no-writes", action="store_true",
                       help="don't test writes (read-only)")
    audit.add_argument("--no-rpc", action="store_true",
                       help="don't test RPC functions")
    audit.add_argument("--output-json", type=Path, help="save results to JSON")

    # Firebase Security Rules (local file).
    rules = sub.add_parser("scan-rules", parents=[report],
                           help="static analysis of Firebase Security Rules")
    rules.add_argument("--rules", type=Path, required=True, help="path to the rules file")
    rules.add_argument("--service", choices=["firestore", "storage", "database", "rtdb"],
                       help="service the rules belong to (detected from the filename if omitted)")

    # Local web platform over the saved-targets database.
    srv = sub.add_parser("serve", help="opens the local web platform (targets dashboard)")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8080)
    srv.add_argument("--no-browser", action="store_true", help="don't open the browser automatically")
    return parser


def _db_warnings(info: dict) -> list[str]:
    out = []
    if info["connected_as_superuser"]:
        out.append(f"connected as a superuser ({info['connected_as']}); prefer a dedicated read-only role")
    if not info["read_only"]:
        out.append("the session isn't in read-only mode")
    if info["missing_roles"]:
        out.append(f"roles missing on the target: {', '.join(info['missing_roles'])}")
    if info["missing_schemas"]:
        out.append(f"schemas missing on the target: {', '.join(info['missing_schemas'])}")
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
            "firebase_config": dict(result.firebase_config),  # Firebase web config is public by design (apiKey included)
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
        stacks = ", ".join(f"{s.name} ({s.confidence})" for s in result.stacks) or "not identified"
        rows.append(("stack", stacks))
        if result.firebase_config:
            rows.append(("firebase", ", ".join(
                f"{k}={v}" for k, v in result.firebase_config.items())))
        for inst in result.supabase_instances:
            rows.append(("supabase", f"{inst.url}  (keys: {', '.join(k['role'] for k in inst.keys) or 'none'})"))
        extra = [report.kv_table(rows)]
        if result.endpoints:
            extra += [Text("Discovered endpoints:", style="bold"), report.endpoints_table(result.endpoints)]
        if result.recommendations:
            extra += [Text("Recommendations:", style="bold"),
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
        print("warning: --probe-writes may insert rows into tables writable by anon", file=sys.stderr)
    if opt.include_destructive:
        print("warning: --include-destructive calls RPCs with a destructive-sounding name; use only on your own/test target",
              file=sys.stderr)


def _detect(args) -> tuple[dict, list[Finding]]:
    if args.url:
        # Similar to recon: fetches HTML + JS scripts to find keys
        text = fetch_text(args.url)
        # Extract JS scripts to look for keys (same as recon)
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
        print(f"no Supabase instance found in {source}", file=sys.stderr)
        return {"provider": "supabase-api", "target": source}, []

    for inst in instances:
        print(f"detected: {inst.url}", file=sys.stderr)
        for k in inst.keys:
            flag = "  <<< service_role (critical if it came from the client)" if k["role"] == "service_role" else ""
            print(f"  {k['role']} key (ref={k['ref']}): {k['key'][:24]}…{flag}", file=sys.stderr)

    if not args.scan:
        return {"provider": "supabase-api", "target": source}, []

    opt = _options(args)
    _probe_warnings(opt)
    findings: list[Finding] = []
    for inst in instances:
        if not inst.anon_key:
            print(f"warning: {inst.url} has no usable key; skipping scan", file=sys.stderr)
            continue
        findings += SupabaseApiScanner(inst.url, inst.anon_key, opt).scan()
    return {"provider": "supabase-api", "target": source}, findings


def _read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise AdapterError(f"couldn't read {path}: {e}") from None


def _build_db_adapter(args):
    dsn = os.environ.get(args.dsn_env)
    if not dsn:
        raise AdapterError(f"set the {args.dsn_env} environment variable with the target's DSN")
    target = parse_dsn(dsn)
    if args.scope:  # optional; when present, the target must be in the allowlist
        authorize(target, load_scope(args.scope))
    return PROVIDERS[args.provider](target, roles=args.roles, schemas=args.schemas)


def dispatch(args) -> int:
    try:
        if args.command in ("check", "scan"):
            adapter = _build_db_adapter(args)
            info = adapter.check()
            for w in _db_warnings(info):
                print(f"warning: {w}", file=sys.stderr)
            if args.command == "check":
                print(json.dumps(info, indent=2, ensure_ascii=False))
                return 0
        elif args.command == "recon":
            opt = options_for_level(args.level)
            # explicit flags can escalate beyond the level
            opt.probe_writes |= args.probe_writes
            opt.probe_rpc |= args.probe_rpc
            opt.include_destructive |= args.include_destructive
            _probe_warnings(opt)
            result = Recon(args.url, opt, level=args.level).run()
            from permiscan import store
            store.enroll(result, "recon-cli")
            return _emit_recon(result, args)
        elif args.command == "serve":
            from permiscan.serve import serve
            serve(args.host, args.port, open_browser=not args.no_browser)
            return 0
        elif args.command == "batch":
            opt = _options(args)
            _probe_warnings(opt)

            # Load URLs
            if args.file:
                urls = load_urls_from_file(args.file)
                print(f"Loaded {len(urls)} URLs from {args.file}", file=sys.stderr)
            else:
                urls = args.urls

            if not urls:
                raise AdapterError("no URL provided")

            # Progress callback
            def progress(completed, total, result):
                status = "[OK]" if result.success else "[X]"
                print(f"[{completed}/{total}] {status} {result.url} ({result.scan_time:.2f}s)", file=sys.stderr)

            print(f"Starting a scan of {len(urls)} sites with {args.workers} workers...", file=sys.stderr)
            results, summary = scan_batch(urls, opt, args.workers, progress)

            # Save files if requested
            if args.output_json:
                save_json(results, summary, args.output_json)
                print(f"JSON saved to {args.output_json}", file=sys.stderr)
            if args.output_csv:
                save_csv(results, summary, args.output_csv)
                print(f"CSV saved to {args.output_csv}", file=sys.stderr)

            # Print the report
            print_text_report(results, summary)

            # Exit with an error if there are critical findings
            if summary.critical_findings > 0:
                return EXIT_FAIL_ON
            return 0
        elif args.command == "audit":
            # Set up automatic options
            opt = ApiScanOptions(
                rows=1,
                probe_writes=not args.no_writes,
                probe_rpc=not args.no_rpc,
                include_destructive=False,  # never calls destructive RPCs automatically
            )

            # Load instances
            if args.from_batch:
                instances = load_instances_from_batch_json(args.from_batch)
                print(f"Loaded {len(instances)} instances from the batch JSON", file=sys.stderr)
            elif args.file:
                instances = load_instances_from_file(args.file)
                print(f"Loaded {len(instances)} URLs from {args.file}", file=sys.stderr)
            else:
                instances = [(url, None) for url in args.urls]

            if not instances:
                raise AdapterError("no instance provided")

            # Progress callback
            def progress(completed, total, result):
                status = "[OK]" if result.success else "[X]"
                key_status = "[KEY]" if result.key_found else "[NOKEY]"
                print(f"[{completed}/{total}] {status} {key_status} {result.supabase_url} ({result.scan_time:.2f}s)", file=sys.stderr)

            print(f"Starting an audit of {len(instances)} instances with {args.workers} workers...", file=sys.stderr)
            print(f"Mode: probe_writes={opt.probe_writes}, probe_rpc={opt.probe_rpc}", file=sys.stderr)
            results, summary = audit_supabase_instances(instances, opt, args.workers, progress)

            # Save JSON if requested
            if args.output_json:
                save_audit_json(results, summary, args.output_json)
                print(f"JSON saved to {args.output_json}", file=sys.stderr)

            # Print the report
            print_audit_report(results, summary)

            # Exit with an error if there are critical findings
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
                raise AdapterError(f"set the {args.key_env} environment variable with the anon key")
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
        print(f"scope error: {e}", file=sys.stderr)
        return EXIT_SCOPE
    except AdapterError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR

    return _emit(info, findings, started, finished, args)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:  # no arguments: interactive menu
        from permiscan.menu import run_menu
        return run_menu()
    return dispatch(_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
