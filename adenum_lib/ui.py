from __future__ import annotations

from typing import Iterable, Mapping, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console(highlight=False)

_VERBOSE = False


_SKULL_ART = r"""
   █▀▀█ █▀▀▄ █▀▀ █▄░█ █░░█ █▀▄▀█
   █▄▄█ █░░█ █▀▀ █░▀█ █░░█ █░▀░█
   ▀░░▀ ▀▀▀░ ▀▀▀ ▀░░▀ ░▀▀▀ ▀░░░▀

   Active Directory  Universal  Enumerator
                                       by Nodir
"""


def show_banner() -> None:
    text = Text(_SKULL_ART, style="bold red")
    console.print(text)


def set_verbose(value: bool) -> None:
    global _VERBOSE
    _VERBOSE = value


def is_verbose() -> bool:
    return _VERBOSE


def banner(stage: int, ip: str, extras: dict[str, str] | None = None) -> None:
    body = Text()
    body.append(f"adenum  Stage {stage}\n", style="bold cyan")
    body.append(f"target: {ip}\n", style="white")
    for key, value in (extras or {}).items():
        body.append(f"{key:>8}: ", style="dim")
        body.append(f"{value}\n", style="bold")
    console.print(Panel(body, border_style="cyan", padding=(0, 2)))


def section(title: str) -> None:
    console.rule(f"[bold cyan]{title}[/bold cyan]", style="cyan")


def info(msg: str) -> None:
    console.print(f"[cyan][*][/cyan] {msg}")


def good(msg: str) -> None:
    console.print(f"[green][+][/green] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow][!][/yellow] {msg}")


def bad(msg: str) -> None:
    console.print(f"[red][x][/red] {msg}")


def crit(msg: str) -> None:
    console.print(f"[bold red][CRIT][/bold red] {msg}")


def cmd(args: Sequence[str]) -> None:
    if _VERBOSE:
        rendered = " ".join(args)
        console.print(f"[dim]$ {rendered}[/dim]")


def explain(msg: str) -> None:
    if _VERBOSE:
        console.print(f"  [dim italic]{msg}[/dim italic]")


def table(title: str, headers: Sequence[str], rows: Iterable[Sequence[str]]) -> None:
    tbl = Table(title=title, title_style="bold", border_style="dim", show_lines=False)
    for header in headers:
        tbl.add_column(header, overflow="fold")
    rows_list = list(rows)
    if not rows_list:
        console.print(f"[dim](no rows for: {title})[/dim]")
        return
    for row in rows_list:
        tbl.add_row(*[str(value) for value in row])
    console.print(tbl)


def kv_block(title: str, items: Mapping[str, object]) -> None:
    if not items:
        return
    body = Text()
    for key, value in items.items():
        if value is None or value == "" or value == [] or value == set():
            continue
        body.append(f"{key:>22}: ", style="dim cyan")
        if isinstance(value, (list, set, tuple)):
            body.append(", ".join(str(item) for item in value) + "\n", style="white")
        else:
            body.append(f"{value}\n", style="white")
    if body:
        console.print(Panel(body, title=title, border_style="green", padding=(0, 2)))


def next_step(suggestion: str, why: str | None = None) -> None:
    body = Text()
    body.append("next: ", style="bold yellow")
    body.append(suggestion + "\n", style="bold white")
    if why:
        body.append(why, style="dim")
    console.print(Panel(body, border_style="yellow", padding=(0, 2)))
