"""Pretty terminal rendering with rich, shared by every command.

Keeps a single place for severity colors, finding panels (with a reproducible PoC),
and summary tables. JSON output doesn't go through here — it stays plain text, for machines.
"""

from collections import Counter
from io import StringIO

from rich.box import ROUNDED, SIMPLE
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from permiscan.findings import Finding, Severity

# Label (text) and panel border color by severity.
_LABEL = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold dark_orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "grey62",
}
_BORDER = {
    Severity.CRITICAL: "red", Severity.HIGH: "dark_orange3", Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan", Severity.INFO: "grey42",
}


def console(file=None) -> Console:
    # For a file: no color and a fixed width, so the saved text stays clean.
    if file is not None:
        return Console(file=file, no_color=True, width=100, highlight=False, emoji=False)
    return Console(highlight=False)


def severity_summary(findings: list[Finding]) -> Text:
    counts = Counter(f.severity for f in findings)
    text = Text(f"{len(findings)} finding(s)")
    shown = [s for s in Severity if counts[s]]
    if shown:
        text.append("  ")
        for i, s in enumerate(shown):
            if i:
                text.append(" · ")
            text.append(f"{counts[s]} {s.value}", style=_LABEL[s])
    return text


def finding_panel(f: Finding) -> Panel:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="grey62", justify="right", no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("resource", Text(f.resource, style="bold"))
    refs = " · ".join(x for x in (f.cwe, f.owasp) if x)
    meta = f"{f.rule_id} · confidence {f.confidence.value}" + (f" · {refs}" if refs else "")
    grid.add_row("rule", Text(meta, style="grey70"))
    grid.add_row("", f.description)
    grid.add_row("fix", f.remediation.summary)
    if f.remediation.sql:
        grid.add_row("", Text(f.remediation.sql, style="green"))
    if f.poc:
        grid.add_row("PoC", Text(f.poc, style="bold cyan"))
    title = Text(f" {f.severity.value.upper()} ", style=_LABEL[f.severity])
    title.append(Text(f"  {f.title}", style="bold default"))
    return Panel(grid, title=title, title_align="left", border_style=_BORDER[f.severity], box=ROUNDED)


def findings_group(header: str, findings: list[Finding], extra: list | None = None) -> Group:
    parts: list = [Rule(Text(header, style="bold"), style="grey42"), severity_summary(findings)]
    if extra:
        parts += ["", *extra]
    if findings:
        parts += ["", *[p for f in findings for p in (finding_panel(f),)]]
    else:
        parts += ["", Text("No findings.", style="green")]
    return Group(*parts)


def kv_table(rows: list[tuple[str, str]]) -> Table:
    t = Table.grid(padding=(0, 1))
    t.add_column(style="grey62", justify="right", no_wrap=True)
    t.add_column(overflow="fold")
    for k, v in rows:
        t.add_row(k, v)
    return t


def endpoints_table(endpoints) -> Table:
    t = Table(box=SIMPLE, show_edge=False, pad_edge=False)
    t.add_column("status", justify="right")
    t.add_column("path")
    t.add_column("type", style="grey62")
    for e in endpoints:
        style = "green" if e.status < 400 else "grey62"
        t.add_row(Text(str(e.status), style=style), e.path, e.content_type or "")
    return t


def counts_line(sev_counts: dict[str, int]) -> Text:
    """Colored line of totals by severity, from names ('critical'…)."""
    text = Text()
    first = True
    for sev in Severity:
        n = sev_counts.get(sev.value, 0)
        if not n:
            continue
        if not first:
            text.append(" · ")
        text.append(f"{n} {sev.value}", style=_LABEL[sev])
        first = False
    if first:
        text.append("none", style="green")
    return text


def summary_block(title: str, rows: list[tuple[str, str]], sev_counts: dict[str, int]) -> Group:
    return Group(
        Rule(Text(title, style="bold"), style="grey42"),
        kv_table(rows),
        Text("findings: ", style="grey62").append_text(counts_line(sev_counts)),
    )


def render(renderable, output=None) -> int:
    """Prints to the terminal (with color) or writes plain text to a file."""
    if output is not None:
        buf = StringIO()
        console(buf).print(renderable)
        output.write_text(buf.getvalue(), encoding="utf-8")
    else:
        console().print(renderable)
    return 0
