"""Interactive menu: runs when `permiscan` is launched with no arguments.

A lean flow — pick the mode, the scan LEVEL (that's it), the target, and the rest is
automatic: recon identifies the stack and digs in on its own (enumerates, and at
level 3, extracts).
"""

from argparse import Namespace
from pathlib import Path

from permiscan import store
from permiscan.discovery import SCAN_LEVELS, Recon
from permiscan.survey import (
    has_resources, list_scans, load_survey, load_urls, next_scan_path, save_survey, survey_many,
)


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        return input(f"{prompt}{suffix}: ").strip() or default
    except EOFError:
        return default


def _ask_level() -> int:
    while True:
        raw = _ask("Scan level (1=minimal  2=medium  3=maximum/aggressive)", "2")
        if raw in ("1", "2", "3"):
            return int(raw)
        print("Choose 1, 2 or 3.")


def _print_menu() -> None:
    from rich.panel import Panel
    from rich.table import Table

    from permiscan import report

    t = Table.grid(padding=(0, 2))
    t.add_column(justify="right", style="bold cyan")
    t.add_column(style="bold")
    t.add_column(style="grey62")
    for num, label, hint in (
        ("1", "Single scan", "one URL, fully automatic"),
        ("2", "Mass scan", "triage a list of sites"),
        ("3", "Explore a saved list", "digs deeper into the targets found in the triage"),
        ("4", "Web platform", "opens the saved-targets dashboard in the browser"),
        ("0", "Exit", ""),
    ):
        t.add_row(num, label, hint)
    report.console().print(Panel(t, title="[bold]PermiScan[/]", border_style="cyan", padding=(1, 2)))


def _print_recon(result) -> None:
    from permiscan.cli import _emit_recon
    _emit_recon(result, Namespace(format="text", output=None, fail_on=None))


def _run_individual() -> None:
    level = _ask_level()
    url = _ask("Target URL (https://…)")
    if not url:
        return
    print(f"\nLevel {level} scan ({SCAN_LEVELS[level]}) on {url}…\n")
    result = Recon(url, level=level).run()
    store.enroll(result, "menu-individual")
    _print_recon(result)


def _collect_urls() -> list[str]:
    raw = _ask("File with URLs (one per line), or empty to type them")
    if raw:
        try:
            return load_urls(Path(raw))
        except OSError as e:
            print(f"error: {e}")
            return []
    typed = _ask("URLs separated by space/comma")
    return [u for u in typed.replace(",", " ").split() if u]


def _survey_table(records: list[dict]):
    from rich.table import Table

    from permiscan import report

    t = Table(title="Triage", title_justify="left", title_style="bold")
    t.add_column("resources", justify="center")
    t.add_column("site")
    t.add_column("stacks", style="grey70")
    t.add_column("findings", justify="right")
    for r in records:
        if r.get("error"):
            t.add_row("—", r["url"], f"[red]error[/]", "")
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
        print("No URLs.")
        return
    print(f"\nTriaging {len(urls)} site(s) at level {level}…\n")

    def progress(i, total, rec):
        tag = "●" if has_resources(rec) else ("x" if rec.get("error") else "·")
        print(f"[{i}/{total}] {tag} {rec['url']}")

    records = survey_many(urls, level=level, progress=progress)
    print()
    _survey_table(records)
    interesting = [r["url"] for r in records if has_resources(r)]
    print(f"\n{len(interesting)} of {len(records)} have resources (Firebase/Supabase or findings).")

    path = next_scan_path()
    save_survey(records, path)
    print(f"Saved to {path}. Explore it later with option 3.")


def _run_explore() -> None:
    scans = list_scans()
    if not scans:
        print("No saved scan yet. Run option 2 (mass scan) first.")
        return
    print("Saved scans:")
    for i, p in enumerate(scans, 1):
        try:
            recs = load_survey(p)
            print(f"  {i}) {p.name}  —  {len(recs)} site(s), {sum(map(has_resources, recs))} with resources")
        except (OSError, ValueError):
            print(f"  {i}) {p.name}  —  [unreadable]")
    pick = _ask("Which scan to explore (number)", "1")
    if not (pick.isdigit() and 1 <= int(pick) <= len(scans)):
        print("Invalid option.")
        return
    try:
        records = load_survey(scans[int(pick) - 1])
    except (OSError, ValueError) as e:
        print(f"error: {e}")
        return
    targets = [r["url"] for r in records if has_resources(r)]
    if not targets:
        print("No target with resources in the triage.")
        return
    print(f"{len(targets)} target(s) with resources. Exploring in depth…")
    level = _ask_level()
    for url in targets:
        print(f"\n{'─' * 60}\n{url}\n")
        try:
            result = Recon(url, level=level).run()
            store.enroll(result, "menu-explore")
            _print_recon(result)
        except Exception as e:  # noqa: BLE001
            print(f"error on {url}: {e}")


def _run_web() -> None:
    from permiscan.serve import serve

    n = store.stats()["targets"]
    print(f"{n} target(s) in the database. Opening the web platform…")
    serve()


_MODES = {"1": _run_individual, "2": _run_mass, "3": _run_explore, "4": _run_web}


def run_menu() -> int:
    while True:
        _print_menu()
        choice = _ask("Choose")
        if choice in ("0", "", "exit", "q"):
            return 0
        action = _MODES.get(choice)
        if not action:
            print("Invalid option.")
            continue
        try:
            action()
        except KeyboardInterrupt:
            print("\nInterrupted.")
        if not _ask("\nDo something else? (y/N)").lower().startswith("y"):
            return 0
