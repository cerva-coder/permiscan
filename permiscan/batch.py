"""Processamento em massa de sites para detecção de Supabase e outras exposições."""

import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from permiscan.adapters.base import AdapterError
from permiscan.discovery import Recon, ReconResult, ApiScanOptions
from permiscan.findings import Finding, Severity


@dataclass
class BatchResult:
    url: str
    success: bool = False
    error: str | None = None
    stacks: list[str] = field(default_factory=list)
    has_supabase: bool = False
    has_firebase: bool = False
    supabase_instances: list[str] = field(default_factory=list)
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
            "url": self.url,
            "success": self.success,
            "error": self.error,
            "stacks": self.stacks,
            "has_supabase": self.has_supabase,
            "has_firebase": self.has_firebase,
            "supabase_instances": self.supabase_instances,
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
class BatchSummary:
    total: int = 0
    successful: int = 0
    failed: int = 0
    with_supabase: int = 0
    with_firebase: int = 0
    with_findings: int = 0
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
            "with_supabase": self.with_supabase,
            "with_firebase": self.with_firebase,
            "with_findings": self.with_findings,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "info_findings": self.info_findings,
            "scan_time": self.scan_time,
        }


def _scan_site(url: str, options: ApiScanOptions) -> BatchResult:
    """Scaneia um único site e retorna BatchResult."""
    start = datetime.now(UTC)
    result = BatchResult(url=url)
    
    try:
        recon = Recon(url, options)
        recon_result = recon.run()
        
        result.success = True
        result.stacks = [s.name for s in recon_result.stacks]
        result.has_supabase = any(s.name == "supabase" for s in recon_result.stacks)
        result.has_firebase = bool(recon_result.firebase_config)
        result.supabase_instances = [inst.url for inst in recon_result.supabase_instances]
        result.findings_count = len(recon_result.findings)
        result.findings = [f.model_dump(mode="json") for f in recon_result.findings]
        
        # Conta por severidade
        for f in recon_result.findings:
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
        
    except AdapterError as e:
        result.success = False
        result.error = str(e)
    except Exception as e:
        result.success = False
        result.error = f"Erro inesperado: {str(e)}"
    
    result.scan_time = (datetime.now(UTC) - start).total_seconds()
    return result


def scan_batch(
    urls: list[str],
    options: ApiScanOptions | None = None,
    max_workers: int = 10,
    progress_callback: callable | None = None,
) -> tuple[list[BatchResult], BatchSummary]:
    """Processa uma lista de URLs em paralelo."""
    options = options or ApiScanOptions()
    results: list[BatchResult] = []
    summary = BatchSummary(total=len(urls))
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submete todos os jobs
        future_to_url = {executor.submit(_scan_site, url, options): url for url in urls}
        
        # Coleta resultados conforme completam
        for future in as_completed(future_to_url):
            result = future.result()
            results.append(result)
            
            # Atualiza summary
            if result.success:
                summary.successful += 1
                if result.has_supabase:
                    summary.with_supabase += 1
                if result.has_firebase:
                    summary.with_firebase += 1
                if result.findings_count > 0:
                    summary.with_findings += 1
                summary.total_findings += result.findings_count
                summary.critical_findings += result.critical_count
                summary.high_findings += result.high_count
                summary.medium_findings += result.medium_count
                summary.low_findings += result.low_count
                summary.info_findings += result.info_count
            else:
                summary.failed += 1
            
            summary.scan_time += result.scan_time
            
            # Callback de progresso
            if progress_callback:
                progress_callback(len(results), len(urls), result)
    
    # Ordena resultados por URL
    results.sort(key=lambda r: r.url)
    return results, summary


def load_urls_from_file(path: Path) -> list[str]:
    """Carrega URLs de um arquivo (uma por linha)."""
    urls = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            if not line.startswith(("http://", "https://")):
                line = f"https://{line}"
            urls.append(line)
    return urls


def save_json(results: list[BatchResult], summary: BatchSummary, output: Path) -> None:
    """Salva resultados em JSON."""
    data = {
        "summary": summary.to_dict(),
        "results": [r.to_dict() for r in results],
        "generated_at": datetime.now(UTC).isoformat(),
    }
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def save_csv(results: list[BatchResult], summary: BatchSummary, output: Path) -> None:
    """Salva resultados em CSV (resumo por site)."""
    fieldnames = [
        "url", "success", "error", "stacks", "has_supabase", "has_firebase",
        "supabase_instances", "findings_count", "critical_count", "high_count",
        "medium_count", "low_count", "info_count", "scan_time"
    ]
    
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        # Header com summary
        writer.writerow({
            "url": "# SUMMARY",
            "success": summary.total,
            "error": f"successful={summary.successful}, failed={summary.failed}",
            "stacks": f"supabase={summary.with_supabase}, firebase={summary.with_firebase}",
            "has_supabase": summary.with_findings,
            "has_firebase": summary.total_findings,
            "supabase_instances": f"critical={summary.critical_findings}, high={summary.high_findings}",
            "findings_count": f"medium={summary.medium_findings}, low={summary.low_findings}, info={summary.info_findings}",
            "critical_count": "",
            "high_count": "",
            "medium_count": "",
            "low_count": "",
            "info_count": "",
            "scan_time": f"{summary.scan_time:.2f}s",
        })
        
        for r in results:
            writer.writerow({
                "url": r.url,
                "success": r.success,
                "error": r.error or "",
                "stacks": ", ".join(r.stacks),
                "has_supabase": r.has_supabase,
                "has_firebase": r.has_firebase,
                "supabase_instances": ", ".join(r.supabase_instances),
                "findings_count": r.findings_count,
                "critical_count": r.critical_count,
                "high_count": r.high_count,
                "medium_count": r.medium_count,
                "low_count": r.low_count,
                "info_count": r.info_count,
                "scan_time": f"{r.scan_time:.2f}",
            })


def print_text_report(results: list[BatchResult], summary: BatchSummary) -> None:
    """Imprime relatório em texto (rich)."""
    from rich.table import Table
    from rich.text import Text

    from permiscan import report

    avg = summary.scan_time / summary.total if summary.total else 0
    sev = {"critical": summary.critical_findings, "high": summary.high_findings,
           "medium": summary.medium_findings, "low": summary.low_findings, "info": summary.info_findings}
    rows = [
        ("sites", f"{summary.total}  ([green]{summary.successful} ok[/], [red]{summary.failed} falha[/])"),
        ("stacks", f"Supabase: {summary.with_supabase}  ·  Firebase: {summary.with_firebase}"),
        ("sites c/ findings", str(summary.with_findings)),
        ("tempo", f"{summary.scan_time:.1f}s total · {avg:.2f}s/site"),
    ]
    con = report.console()
    con.print(report.summary_block("Scan em massa", rows, sev))

    critical_sites = [r for r in results if r.critical_count > 0]
    if critical_sites:
        t = Table(title="Sites com findings críticos", title_style="bold red", title_justify="left")
        t.add_column("site"); t.add_column("crit", justify="right", style="red")
        t.add_column("high", justify="right", style="dark_orange3"); t.add_column("findings")
        for r in critical_sites:
            titles = ", ".join(f.get("title", "") for f in r.findings if f.get("severity") == "critical")
            t.add_row(r.url, str(r.critical_count), str(r.high_count), titles)
        con.print(t)

    failed_sites = [r for r in results if not r.success]
    if failed_sites:
        t = Table(title=f"Sites que falharam ({len(failed_sites)})", title_style="bold", title_justify="left")
        t.add_column("site"); t.add_column("erro", style="grey62")
        for r in failed_sites:
            t.add_row(r.url, str(r.error))
        con.print(t)
