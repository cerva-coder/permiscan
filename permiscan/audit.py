"""Automatic bulk auditing of Supabase instances.

This module automatically extracts keys from the original sites and runs a full
RLS vulnerability scan, with no user interaction.
"""

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from permiscan.adapters.base import AdapterError
from permiscan.adapters.supabase_api import (
    ApiScanOptions,
    SupabaseApiScanner,
    detect_instances,
    fetch_text,
)
from permiscan.discovery import script_srcs
from permiscan.findings import Finding, Severity


@dataclass
class AuditResult:
    supabase_url: str
    source_url: str | None = None
    success: bool = False
    error: str | None = None
    key_found: bool = False
    key_source: str | None = None
    findings_count: int = 0
    findings: list[dict] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "supabase_url": self.supabase_url,
            "source_url": self.source_url,
            "success": self.success,
            "error": self.error,
            "key_found": self.key_found,
            "key_source": self.key_source,
            "findings_count": self.findings_count,
            "findings": self.findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "scan_time": self.scan_time,
        }


@dataclass
class AuditSummary:
    total: int = 0
    successful: int = 0
    failed: int = 0
    keys_found: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "successful": self.successful,
            "failed": self.failed,
            "keys_found": self.keys_found,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "info_findings": self.info_findings,
            "scan_time": self.scan_time,
        }


def _extract_key_from_url(source_url: str) -> tuple[list[tuple[str, str]], str | None]:
    """Tries to extract anon keys from a site's URL. Returns a list of (key, supabase_url)."""
    try:
        # Download the HTML + scripts
        text = fetch_text(source_url)
        for src in script_srcs(text, source_url):
            try:
                text += "\n" + fetch_text(src)
            except AdapterError:
                continue

        # Detect instances
        instances = detect_instances(text)
        if not instances:
            return [], None

        # Return every key paired with its URL
        keys = []
        for inst in instances:
            if inst.anon_key:
                keys.append((inst.anon_key, inst.url))

        return keys, f"extracted from {source_url}"
    except Exception:
        return [], None


def _audit_instance(supabase_url: str, source_url: str | None, options: ApiScanOptions) -> AuditResult:
    """Audits a single Supabase instance."""
    start = datetime.now(UTC)
    result = AuditResult(supabase_url=supabase_url, source_url=source_url)

    try:
        # Try to extract keys
        keys = []
        key_source = None

        if source_url:
            keys, key_source = _extract_key_from_url(source_url)

        if not keys:
            result.success = False
            result.error = "anon key not found on the source site"
            result.scan_time = (datetime.now(UTC) - start).total_seconds()
            return result

        result.key_found = True
        result.key_source = key_source

        # Try each key until one works
        last_error = None
        for key, key_url in keys:
            try:
                # Run a full scan
                scanner = SupabaseApiScanner(supabase_url, key, options)
                findings = scanner.scan()

                result.success = True
                result.findings_count = len(findings)
                result.findings = [f.model_dump(mode="json") for f in findings]

                # Count by severity
                for f in findings:
                    if f.severity == Severity.CRITICAL:
                        result.critical_count += 1
                    elif f.severity == Severity.HIGH:
                        result.high_count += 1
                    elif f.severity == Severity.MEDIUM:
                        result.medium_count += 1
                    elif f.severity == Severity.LOW:
                        result.low_count += 1
                    else:
                        result.info_count += 1

                result.scan_time = (datetime.now(UTC) - start).total_seconds()
                return result
            except AdapterError as e:
                last_error = str(e)
                continue

        # None of the keys worked
        result.success = False
        result.error = f"all keys failed. Last error: {last_error}"

    except Exception as e:
        result.success = False
        result.error = f"unexpected error: {str(e)}"

    result.scan_time = (datetime.now(UTC) - start).total_seconds()
    return result


def audit_supabase_instances(
    instances: list[tuple[str, str | None]],  # (supabase_url, source_url)
    options: ApiScanOptions | None = None,
    max_workers: int = 10,
    progress_callback: callable | None = None,
) -> tuple[list[AuditResult], AuditSummary]:
    """Audits a list of Supabase instances in parallel."""
    options = options or ApiScanOptions(
        rows=1,
        probe_writes=True,  # test writes automatically
        probe_rpc=True,     # test RPC automatically
        include_destructive=False,  # do NOT call destructive functions by default
    )

    results: list[AuditResult] = []
    summary = AuditSummary(total=len(instances))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_inst = {
            executor.submit(_audit_instance, supabase_url, source_url, options): (supabase_url, source_url)
            for supabase_url, source_url in instances
        }

        for future in as_completed(future_to_inst):
            result = future.result()
            results.append(result)

            # Update the summary
            if result.success:
                summary.successful += 1
                if result.key_found:
                    summary.keys_found += 1
                summary.total_findings += result.findings_count
                summary.critical_findings += result.critical_count
                summary.high_findings += result.high_count
                summary.medium_findings += result.medium_count
                summary.low_findings += result.low_count
                summary.info_findings += result.info_count
            else:
                summary.failed += 1

            summary.scan_time += result.scan_time

            if progress_callback:
                progress_callback(len(results), len(instances), result)

    results.sort(key=lambda r: r.supabase_url)
    return results, summary


def load_instances_from_batch_json(json_path: Path) -> list[tuple[str, str | None]]:
    """Loads Supabase instances from a JSON file generated by the batch command."""
    data = json.loads(json_path.read_text(encoding="utf-8"))
    instances = []

    for r in data.get("results", []):
        if r.get("has_supabase"):
            source_url = r.get("url")
            for supabase_url in r.get("supabase_instances", []):
                instances.append((supabase_url, source_url))

    return instances


def load_instances_from_file(path: Path) -> list[tuple[str, str | None]]:
    """Loads Supabase URLs from a file (one per line)."""
    instances = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            if not line.startswith(("http://", "https://")):
                line = f"https://{line}"
            instances.append((line, None))
    return instances


def save_audit_json(results: list[AuditResult], summary: AuditSummary, output: Path) -> None:
    """Saves results to JSON."""
    data = {
        "summary": summary.to_dict(),
        "results": [r.to_dict() for r in results],
        "generated_at": datetime.now(UTC).isoformat(),
    }
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def print_audit_report(results: list[AuditResult], summary: AuditSummary) -> None:
    """Prints the audit report (rich)."""
    from rich.table import Table

    from permiscan import report

    avg = summary.scan_time / summary.total if summary.total else 0
    sev = {"critical": summary.critical_findings, "high": summary.high_findings,
           "medium": summary.medium_findings, "low": summary.low_findings, "info": summary.info_findings}
    rows = [
        ("instances", f"{summary.total}  ([green]{summary.successful} ok[/], [red]{summary.failed} failed[/])"),
        ("keys found", str(summary.keys_found)),
        ("time", f"{summary.scan_time:.1f}s total · {avg:.2f}s/instance"),
    ]
    con = report.console()
    con.print(report.summary_block("Supabase audit (RLS)", rows, sev))

    vuln = [r for r in results if r.critical_count or r.high_count]
    if vuln:
        t = Table(title="Vulnerable instances", title_style="bold red", title_justify="left")
        t.add_column("instance"); t.add_column("crit", justify="right", style="red")
        t.add_column("high", justify="right", style="dark_orange3"); t.add_column("source", style="grey62")
        for r in sorted(vuln, key=lambda r: (-r.critical_count, -r.high_count)):
            t.add_row(r.supabase_url, str(r.critical_count), str(r.high_count), r.source_url or "")
        con.print(t)

    failed = [r for r in results if not r.success]
    if failed:
        t = Table(title=f"Failed instances ({len(failed)})", title_style="bold", title_justify="left")
        t.add_column("instance"); t.add_column("error", style="grey62")
        for r in failed:
            t.add_row(r.supabase_url, str(r.error))
        con.print(t)
