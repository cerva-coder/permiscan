"""Auditoria automática de instâncias Supabase em massa.

Este módulo extrai automaticamente chaves dos sites originais e faz scan completo
de vulnerabilidades RLS, sem interação do usuário.
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
    """Tenta extrair chaves anon de uma URL do site. Retorna lista de (chave, url_supabase)."""
    try:
        # Baixa HTML + scripts
        text = fetch_text(source_url)
        for src in script_srcs(text, source_url):
            try:
                text += "\n" + fetch_text(src)
            except AdapterError:
                continue
        
        # Detecta instâncias
        instances = detect_instances(text)
        if not instances:
            return [], None
        
        # Retorna todas as chaves com suas URLs associadas
        keys = []
        for inst in instances:
            if inst.anon_key:
                keys.append((inst.anon_key, inst.url))
        
        return keys, f"extraido de {source_url}"
    except Exception:
        return [], None


def _audit_instance(supabase_url: str, source_url: str | None, options: ApiScanOptions) -> AuditResult:
    """Audita uma única instância Supabase."""
    start = datetime.now(UTC)
    result = AuditResult(supabase_url=supabase_url, source_url=source_url)
    
    try:
        # Tenta extrair chaves
        keys = []
        key_source = None
        
        if source_url:
            keys, key_source = _extract_key_from_url(source_url)
        
        if not keys:
            result.success = False
            result.error = "chave anon nao encontrada no site de origem"
            result.scan_time = (datetime.now(UTC) - start).total_seconds()
            return result
        
        result.key_found = True
        result.key_source = key_source
        
        # Tenta cada chave até encontrar uma que funcione
        last_error = None
        for key, key_url in keys:
            try:
                # Faz scan completo
                scanner = SupabaseApiScanner(supabase_url, key, options)
                findings = scanner.scan()
                
                result.success = True
                result.findings_count = len(findings)
                result.findings = [f.model_dump(mode="json") for f in findings]
                
                # Conta por severidade
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
        
        # Nenhuma chave funcionou
        result.success = False
        result.error = f"todas as chaves falharam. Ultimo erro: {last_error}"
        
    except Exception as e:
        result.success = False
        result.error = f"Erro inesperado: {str(e)}"
    
    result.scan_time = (datetime.now(UTC) - start).total_seconds()
    return result


def audit_supabase_instances(
    instances: list[tuple[str, str | None]],  # (supabase_url, source_url)
    options: ApiScanOptions | None = None,
    max_workers: int = 10,
    progress_callback: callable | None = None,
) -> tuple[list[AuditResult], AuditSummary]:
    """Audita uma lista de instâncias Supabase em paralelo."""
    options = options or ApiScanOptions(
        rows=1,
        probe_writes=True,  # Testa escrita automaticamente
        probe_rpc=True,     # Testa RPC automaticamente
        include_destructive=False,  # NÃO chama funções destrutivas por padrão
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
            
            # Atualiza summary
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
    """Carrega instâncias Supabase de um JSON gerado pelo comando batch."""
    data = json.loads(json_path.read_text(encoding="utf-8"))
    instances = []
    
    for r in data.get("results", []):
        if r.get("has_supabase"):
            source_url = r.get("url")
            for supabase_url in r.get("supabase_instances", []):
                instances.append((supabase_url, source_url))
    
    return instances


def load_instances_from_file(path: Path) -> list[tuple[str, str | None]]:
    """Carrega URLs Supabase de um arquivo (uma por linha)."""
    instances = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            if not line.startswith(("http://", "https://")):
                line = f"https://{line}"
            instances.append((line, None))
    return instances


def save_audit_json(results: list[AuditResult], summary: AuditSummary, output: Path) -> None:
    """Salva resultados em JSON."""
    data = {
        "summary": summary.to_dict(),
        "results": [r.to_dict() for r in results],
        "generated_at": datetime.now(UTC).isoformat(),
    }
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def print_audit_report(results: list[AuditResult], summary: AuditSummary) -> None:
    """Imprime relatório de auditoria."""
    print("\n" + "=" * 70)
    print("RELATORIO DE AUDITORIA SUPABASE (RLS)")
    print("=" * 70)
    print(f"\nTotal de instancias: {summary.total}")
    print(f"[OK] Sucesso: {summary.successful}")
    print(f"[X] Falha: {summary.failed}")
    print(f"[KEY] Chaves encontradas: {summary.keys_found}")
    print(f"\nVulnerabilidades encontradas:")
    print(f"  - Instancias com findings: {summary.successful}")
    print(f"  - Total de findings: {summary.total_findings}")
    print(f"    - CRITICAL: {summary.critical_findings}")
    print(f"    - HIGH: {summary.high_findings}")
    print(f"    - MEDIUM: {summary.medium_findings}")
    print(f"    - LOW: {summary.low_findings}")
    print(f"    - INFO: {summary.info_findings}")
    print(f"\nTempo total: {summary.scan_time:.2f}s")
    print(f"Tempo medio por instancia: {summary.scan_time / summary.total:.2f}s")
    
    # Mostra instâncias com findings críticos
    critical_insts = [r for r in results if r.critical_count > 0]
    if critical_insts:
        print("\n" + "=" * 70)
        print("INSTANCIAS COM VULNERABILIDADES CRITICAS:")
        print("=" * 70)
        for r in critical_insts:
            print(f"\n{r.supabase_url}")
            print(f"  CRITICAL: {r.critical_count}, HIGH: {r.high_count}")
            if r.source_url:
                print(f"  Fonte: {r.source_url}")
            for f in r.findings:
                if f.get("severity") == "critical":
                    print(f"    - {f.get('title')}")
    
    # Mostra instâncias com HIGH
    high_insts = [r for r in results if r.high_count > 0 and r.critical_count == 0]
    if high_insts:
        print("\n" + "=" * 70)
        print("INSTANCIAS COM VULNERABILIDADES ALTAS:")
        print("=" * 70)
        for r in high_insts:
            print(f"\n{r.supabase_url}")
            print(f"  HIGH: {r.high_count}, MEDIUM: {r.medium_count}")
            if r.source_url:
                print(f"  Fonte: {r.source_url}")
    
    # Mostra instâncias que falharam
    failed_insts = [r for r in results if not r.success]
    if failed_insts:
        print("\n" + "=" * 70)
        print(f"INSTANCIAS QUE FALHARAM ({len(failed_insts)}):")
        print("=" * 70)
        for r in failed_insts:
            print(f"  [X] {r.supabase_url}")
            if r.source_url:
                print(f"      Fonte: {r.source_url}")
            if r.key_found:
                print(f"      Chave encontrada mas rejeitada (401) - mismatch chave/URL")
            print(f"      Erro: {r.error}")
