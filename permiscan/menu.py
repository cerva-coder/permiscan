"""Menu interativo: roda `permiscan` sem argumentos.

Fluxo enxuto — escolhe o modo, o NÍVEL do scan (só isso), o alvo, e o resto é automático:
o recon identifica a stack e vai fundo sozinho (enumera e, no nível 3, extrai).
"""

from argparse import Namespace
from pathlib import Path

from permiscan.discovery import SCAN_LEVELS, Recon
from permiscan.survey import has_resources, load_survey, load_urls, save_survey, survey_many


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        return input(f"{prompt}{suffix}: ").strip() or default
    except EOFError:
        return default


def _ask_level() -> int:
    while True:
        raw = _ask("Nível do scan (1=mínimo  2=médio  3=máximo agressivo)", "2")
        if raw in ("1", "2", "3"):
            return int(raw)
        print("Escolha 1, 2 ou 3.")


def _print_menu() -> None:
    from rich.panel import Panel
    from rich.table import Table

    from permiscan import report

    t = Table.grid(padding=(0, 2))
    t.add_column(justify="right", style="bold cyan")
    t.add_column(style="bold")
    t.add_column(style="grey62")
    for num, label, hint in (
        ("1", "Scan individual", "uma URL, totalmente automático"),
        ("2", "Scan em massa", "triagem de uma lista de sites"),
        ("3", "Explorar lista salva", "aprofunda os alvos achados na triagem"),
        ("0", "Sair", ""),
    ):
        t.add_row(num, label, hint)
    report.console().print(Panel(t, title="[bold]PermiScan[/]", border_style="cyan", padding=(1, 2)))


def _print_recon(result) -> None:
    from permiscan.cli import _emit_recon
    _emit_recon(result, Namespace(format="text", output=None, fail_on=None))


def _run_individual() -> None:
    level = _ask_level()
    url = _ask("URL do alvo (https://…)")
    if not url:
        return
    print(f"\nScan nível {level} ({SCAN_LEVELS[level]}) em {url}…\n")
    _print_recon(Recon(url, level=level).run())


def _collect_urls() -> list[str]:
    raw = _ask("Arquivo com URLs (uma por linha), ou vazio p/ digitar")
    if raw:
        try:
            return load_urls(Path(raw))
        except OSError as e:
            print(f"erro: {e}")
            return []
    typed = _ask("URLs separadas por espaço/vírgula")
    return [u for u in typed.replace(",", " ").split() if u]


def _survey_table(records: list[dict]):
    from rich.table import Table

    from permiscan import report

    t = Table(title="Triagem", title_justify="left", title_style="bold")
    t.add_column("recursos", justify="center")
    t.add_column("site")
    t.add_column("stacks", style="grey70")
    t.add_column("findings", justify="right")
    for r in records:
        if r.get("error"):
            t.add_row("—", r["url"], f"[red]erro[/]", "")
            continue
        mark = "[green]●[/]" if has_resources(r) else "·"
        crit = r["severity_counts"].get("critical", 0) + r["severity_counts"].get("high", 0)
        fcount = f"[red]{len(r['findings'])}[/]" if crit else str(len(r["findings"]))
        t.add_row(mark, r["url"], ", ".join(r["stacks"]) or "—", fcount)
    report.console().print(t)


def _run_mass() -> None:
    level = _ask_level()
    urls = _collect_urls()
    if not urls:
        print("Nenhuma URL.")
        return
    print(f"\nTriando {len(urls)} site(s) no nível {level}…\n")

    def progress(i, total, rec):
        tag = "●" if has_resources(rec) else ("x" if rec.get("error") else "·")
        print(f"[{i}/{total}] {tag} {rec['url']}")

    records = survey_many(urls, level=level, progress=progress)
    print()
    _survey_table(records)
    interesting = [r["url"] for r in records if has_resources(r)]
    print(f"\n{len(interesting)} de {len(records)} com recursos (Firebase/Supabase ou findings).")

    out = _ask("Salvar triagem em arquivo (vazio = não salvar)")
    if out:
        save_survey(records, Path(out))
        print(f"Salvo em {out}. Explore depois com a opção 3.")


def _run_explore() -> None:
    path = _ask("Arquivo da triagem salva (JSON)")
    if not path:
        return
    try:
        records = load_survey(Path(path))
    except (OSError, ValueError) as e:
        print(f"erro: {e}")
        return
    targets = [r["url"] for r in records if has_resources(r)]
    if not targets:
        print("Nenhum alvo com recursos na triagem.")
        return
    print(f"{len(targets)} alvo(s) com recursos. Explorando a fundo…")
    level = _ask_level()
    for url in targets:
        print(f"\n{'─' * 60}\n{url}\n")
        try:
            _print_recon(Recon(url, level=level).run())
        except Exception as e:  # noqa: BLE001
            print(f"erro em {url}: {e}")


_MODES = {"1": _run_individual, "2": _run_mass, "3": _run_explore}


def run_menu() -> int:
    while True:
        _print_menu()
        choice = _ask("Escolha")
        if choice in ("0", "", "sair", "q"):
            return 0
        action = _MODES.get(choice)
        if not action:
            print("Opção inválida.")
            continue
        try:
            action()
        except KeyboardInterrupt:
            print("\nInterrompido.")
        if not _ask("\nFazer outra coisa? (s/N)").lower().startswith("s"):
            return 0
