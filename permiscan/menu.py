"""Menu interativo: roda `permiscan` sem argumentos e ele pergunta o que fazer.

É só um coletor de respostas — monta os mesmos parâmetros que a CLI por argumentos e chama
`cli.dispatch`, reaproveitando adaptadores, relatórios e política de segurança já existentes.
"""

import os
from argparse import Namespace
from getpass import getpass
from pathlib import Path

from permiscan.adapters import PROVIDERS
from permiscan.audit import (
    load_instances_from_batch_json,
    load_instances_from_file,
    print_audit_report,
    save_audit_json,
    audit_supabase_instances,
)
from permiscan.batch import load_urls_from_file, print_text_report, save_csv, save_json, scan_batch
from permiscan.cli import dispatch, _options, _probe_warnings

# Campos que dispatch()/_emit() podem acessar; cada ação sobrescreve o que usa.
_DEFAULTS = dict(
    command=None, provider=None, scope=None, dsn_env="PERMISCAN_DSN", roles=None, schemas=None,
    url=None, key_env="PERMISCAN_ANON_KEY", rows=1, probe_writes=False, probe_rpc=False,
    include_destructive=False, format="text", output=None, fail_on=None,
    rules=None, service=None, file=None, scan=False, urls=None, workers=10,
    output_json=None, output_csv=None, from_batch=None, no_writes=False, no_rpc=False,
)


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        return default or ""
    return value or (default or "")


def _ask_bool(prompt: str, default: bool = False) -> bool:
    hint = "S/n" if default else "s/N"
    value = _ask(f"{prompt} ({hint})").lower()
    return default if not value else value in ("s", "sim", "y", "yes")


def _ask_required(prompt: str) -> str | None:
    """Repete até vir algo; vazio cancela a ação."""
    while True:
        value = _ask(prompt)
        if value:
            return value
        if not _ask_bool("Valor obrigatório. Tentar de novo?", True):
            return None


def _ask_report(ns: Namespace) -> None:
    ns.format = "json" if _ask("Formato (text/json)", "text").lower().startswith("j") else "text"
    out = _ask("Salvar em arquivo (vazio = tela)")
    ns.output = Path(out) if out else None


def _ask_probes(ns: Namespace) -> None:
    ns.probe_writes = _ask_bool("Testar ESCRITA anônima? Pode inserir linhas no alvo", False)
    ns.probe_rpc = _ask_bool("Chamar funções RPC?", False)
    if ns.probe_rpc:
        ns.include_destructive = _ask_bool(
            "Incluir RPCs de nome destrutivo (delete/drop/admin)? Só em alvo próprio/de teste", False)


_ACTIONS = {
    "1": "recon",
    "2": "batch",
    "3": "audit",
    "4": "scan-api",
    "5": "detect",
    "6": "db",
    "7": "scan-rules",
}


def _menu_text() -> str:
    return (
        "\n=== PermiScan ===\n"
        "O que você quer fazer?\n"
        "  1) Reconhecimento automático (só uma URL)\n"
        "  2) Scan em massa (lista de sites)\n"
        "  3) Auditoria automática Supabase (extrai chaves + testa RLS)\n"
        "  4) Varredura externa Supabase (Data API)\n"
        "  5) Detectar credenciais numa página ou arquivo\n"
        "  6) Analisar banco PostgreSQL/Supabase (via DSN)\n"
        "  7) Analisar Firebase Security Rules (arquivo)\n"
        "  0) Sair"
    )


def _build(action: str) -> Namespace | None:
    """Monta o Namespace de uma ação, ou None se o usuário cancelar."""
    ns = Namespace(**_DEFAULTS)

    if action == "recon":
        ns.command = "recon"
        if not (url := _ask_required("URL do alvo (https://…)")):
            return None
        ns.url = url
        _ask_probes(ns)
        _ask_report(ns)

    elif action == "batch":
        ns.command = "batch"
        if _ask_bool("Carregar URLs de arquivo? (não = digitar URLs)", True):
            path = _ask_required("Caminho do arquivo (uma URL por linha)")
            if not path:
                return None
            ns.file = Path(path)
        else:
            urls_input = _ask("URLs (separadas por vírgula ou espaço)")
            if not urls_input:
                return None
            ns.urls = [u.strip() for u in urls_input.replace(",", " ").split() if u.strip()]
        
        ns.workers = int(_ask("Workers paralelos (padrão 10)", "10") or 10)
        _ask_probes(ns)
        
        # Pergunta sobre arquivos de saída
        if _ask_bool("Salvar resultados em JSON?", False):
            json_path = _ask("Caminho do arquivo JSON")
            if json_path:
                ns.output_json = Path(json_path)
        if _ask_bool("Salvar resumo em CSV?", False):
            csv_path = _ask("Caminho do arquivo CSV")
            if csv_path:
                ns.output_csv = Path(csv_path)

    elif action == "audit":
        ns.command = "audit"
        if _ask_bool("Usar JSON do batch? (nao = URLs manuais)", True):
            json_path = _ask("Caminho do JSON do batch")
            if not json_path:
                return None
            ns.from_batch = Path(json_path)
        else:
            if _ask_bool("Carregar URLs de arquivo? (nao = digitar URLs)", True):
                path = _ask("Caminho do arquivo (uma URL por linha)")
                if path:
                    ns.file = Path(path)
            else:
                urls_input = _ask("URLs Supabase (separadas por virgula ou espaço)")
                if urls_input:
                    ns.urls = [u.strip() for u in urls_input.replace(",", " ").split() if u.strip()]
        
        ns.workers = int(_ask("Workers paralelos (padrão 10)", "10") or 10)
        ns.no_writes = not _ask_bool("Testar escrita (POST)? (recomendado)", True)
        ns.no_rpc = not _ask_bool("Testar funcoes RPC? (recomendado)", True)
        
        if _ask_bool("Salvar resultados em JSON?", False):
            json_path = _ask("Caminho do arquivo JSON")
            if json_path:
                ns.output_json = Path(json_path)

    elif action == "scan-api":
        ns.command = "scan-api"
        if not (url := _ask_required("URL do projeto Supabase (https://xxxx.supabase.co)")):
            return None
        ns.url = url
        key = _ask_required("Chave anon/publishable")
        if not key:
            return None
        os.environ[ns.key_env] = key
        ns.rows = max(1, int(_ask("Linhas lidas por tabela", "1") or 1))
        _ask_probes(ns)
        _ask_report(ns)

    elif action == "detect":
        ns.command = "detect"
        if _ask_bool("Ler de uma URL (não = arquivo local)?", True):
            if not (url := _ask_required("URL da página")):
                return None
            ns.url = url
        else:
            path = _ask_required("Caminho do arquivo (HTML/JS/.env)")
            if not path:
                return None
            ns.file = Path(path)
        ns.scan = _ask_bool("Varrer cada instância detectada pela Data API?", False)
        if ns.scan:
            _ask_probes(ns)
        _ask_report(ns)

    elif action == "db":
        ns.command = "scan" if _ask_bool("Rodar varredura (não = só validar conexão)?", True) else "check"
        providers = ", ".join(sorted(PROVIDERS))
        ns.provider = _ask(f"Provedor ({providers})", "supabase")
        if ns.provider not in PROVIDERS:
            print(f"Provedor inválido: {ns.provider}")
            return None
        dsn = getpass("DSN (postgresql://…, não aparece ao digitar): ").strip()
        if not dsn:
            return None
        os.environ[ns.dsn_env] = dsn
        roles = _ask("Papéis a auditar, separados por vírgula (vazio = padrão)")
        ns.roles = [r.strip() for r in roles.split(",") if r.strip()] or None
        schemas = _ask("Schemas, separados por vírgula (vazio = padrão)")
        ns.schemas = [s.strip() for s in schemas.split(",") if s.strip()] or None
        scope = _ask("Arquivo de escopo .toml (vazio = sem allowlist)")
        ns.scope = Path(scope) if scope else None
        if ns.command == "scan":
            _ask_report(ns)

    elif action == "scan-rules":
        ns.command = "scan-rules"
        path = _ask_required("Caminho do arquivo de regras (firestore.rules…)")
        if not path:
            return None
        ns.rules = Path(path)
        svc = _ask("Serviço (firestore/storage/rtdb, vazio = detectar pelo nome)")
        ns.service = svc or None
        _ask_report(ns)

    return ns


def run_menu() -> int:
    while True:
        print(_menu_text())
        choice = _ask("Escolha")
        if choice in ("0", "", "sair", "q"):
            return 0
        action = _ACTIONS.get(choice)
        if not action:
            print("Opção inválida.")
            continue
        ns = _build(action)
        if ns is None:
            print("Ação cancelada.")
            continue
        try:
            # Batch tem tratamento especial para mostrar progresso
            if ns.command == "batch":
                opt = _options(ns)
                _probe_warnings(opt)
                
                # Carrega URLs
                if ns.file:
                    urls = load_urls_from_file(ns.file)
                    print(f"Carregadas {len(urls)} URLs de {ns.file}")
                else:
                    urls = ns.urls
                
                if not urls:
                    print("Nenhuma URL fornecida.")
                    continue
                
                # Callback de progresso
                def progress(completed, total, result):
                    status = "[OK]" if result.success else "[X]"
                    print(f"[{completed}/{total}] {status} {result.url} ({result.scan_time:.2f}s)")
                
                print(f"Iniciando scan de {len(urls)} sites com {ns.workers} workers...")
                results, summary = scan_batch(urls, opt, ns.workers, progress)
                
                # Salva arquivos se solicitado
                if ns.output_json:
                    save_json(results, summary, ns.output_json)
                    print(f"JSON salvo em {ns.output_json}")
                if ns.output_csv:
                    save_csv(results, summary, ns.output_csv)
                    print(f"CSV salvo em {ns.output_csv}")
                
                # Imprime relatório
                print_text_report(results, summary)
            elif ns.command == "audit":
                # Configura opções automáticas
                from permiscan.adapters.supabase_api import ApiScanOptions
                opt = ApiScanOptions(
                    rows=1,
                    probe_writes=not ns.no_writes,
                    probe_rpc=not ns.no_rpc,
                    include_destructive=False,
                )
                
                # Carrega instâncias
                if ns.from_batch:
                    instances = load_instances_from_batch_json(ns.from_batch)
                    print(f"Carregadas {len(instances)} instancias do batch JSON")
                elif ns.file:
                    instances = load_instances_from_file(ns.file)
                    print(f"Carregadas {len(instances)} URLs de {ns.file}")
                else:
                    instances = [(url, None) for url in ns.urls]
                
                if not instances:
                    print("Nenhuma instancia fornecida.")
                    continue
                
                # Callback de progresso
                def progress(completed, total, result):
                    status = "[OK]" if result.success else "[X]"
                    key_status = "[KEY]" if result.key_found else "[NOKEY]"
                    print(f"[{completed}/{total}] {status} {key_status} {result.supabase_url} ({result.scan_time:.2f}s)")
                
                print(f"Iniciando auditoria de {len(instances)} instancias com {ns.workers} workers...")
                print(f"Modo: probe_writes={opt.probe_writes}, probe_rpc={opt.probe_rpc}")
                results, summary = audit_supabase_instances(instances, opt, ns.workers, progress)
                
                # Salva JSON se solicitado
                if ns.output_json:
                    save_audit_json(results, summary, ns.output_json)
                    print(f"JSON salvo em {ns.output_json}")
                
                # Imprime relatório
                print_audit_report(results, summary)
            else:
                dispatch(ns)
        except KeyboardInterrupt:
            print("\nInterrompido.")
        if not _ask_bool("\nFazer outra coisa?", True):
            return 0
