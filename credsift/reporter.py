# credsift/reporter.py
"""
Output formatters for scored CredRecords.

Supports three output modes:
    table  — rich terminal table, sorted by risk_score descending (default)
    csv    — comma-separated, suitable for spreadsheet import
    json   — newline-delimited JSON, suitable for SIEM or further processing
"""

import csv
import json
import sys
from io import StringIO
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich import box

from credsift.parsers import CredRecord


console = Console()


def _risk_color(score: float) -> str:
    """Map a risk score to a rich color string."""
    if score >= 0.8:
        return "bold red"
    if score >= 0.6:
        return "orange3"
    if score >= 0.4:
        return "yellow"
    return "dim"


def _truncate(value: Optional[str], max_len: int = 40) -> str:
    """Truncate a string for display, appending ellipsis if needed."""
    if not value:
        return "—"
    return value if len(value) <= max_len else value[:max_len - 1] + "…"


def _record_to_dict(record: CredRecord) -> dict:
    """Serialize a CredRecord to a plain dictionary for CSV/JSON output."""
    return {
        "email":       record.email or "",
        "username":    record.username or "",
        "domain":      record.domain or "",
        "secret":      record.secret or "",
        "is_hash":     record.is_hash,
        "hash_type":   record.hash_type.value if record.hash_type else "",
        "fmt":         record.fmt.value,
        "source":      record.source or "",
        "risk_score":  record.risk_score,
        "tags":        ",".join(record.tags),
    }


# ── Table output ──────────────────────────────────────────────────────────────

def report_table(
    records: list[CredRecord],
    target_domain: Optional[str] = None,
    top: Optional[int] = None,
) -> None:
    """Print a rich terminal table sorted by risk_score descending."""
    sorted_records = sorted(records, key=lambda r: r.risk_score, reverse=True)
    if top:
        sorted_records = sorted_records[:top]

    title = f"credsift results"
    if target_domain:
        title += f" — {target_domain}"

    table = Table(
        title=title,
        box=box.SIMPLE_HEAD,
        show_lines=False,
        highlight=True,
    )

    table.add_column("score",    style="bold",   width=7,  justify="right")
    table.add_column("email / user",             width=32)
    table.add_column("domain",                   width=20)
    table.add_column("secret",                   width=24)
    table.add_column("type",                     width=14)
    table.add_column("tags",                     width=24)

    for r in sorted_records:
        color  = _risk_color(r.risk_score)
        secret = "[dim]<hash>[/dim]" if r.is_hash else _truncate(r.secret, 24)
        table.add_row(
            f"[{color}]{r.risk_score:.2f}[/{color}]",
            _truncate(r.email or r.username, 32),
            _truncate(r.domain, 20),
            secret,
            r.fmt.value.split(":")[0] + (":" + r.hash_type.value if r.hash_type else ""),
            _truncate(",".join(r.tags), 24),
        )

    console.print()
    console.print(table)
    console.print(
        f"  [dim]showing {len(sorted_records)} of {len(records)} records[/dim]\n"
    )


# ── CSV output ────────────────────────────────────────────────────────────────

def report_csv(
    records: list[CredRecord],
    top: Optional[int] = None,
    output=None,
) -> None:
    """Write CSV to stdout or a file-like object."""
    sorted_records = sorted(records, key=lambda r: r.risk_score, reverse=True)
    if top:
        sorted_records = sorted_records[:top]

    out = output or sys.stdout
    fieldnames = [
        "email", "username", "domain", "secret",
        "is_hash", "hash_type", "fmt", "source", "risk_score", "tags",
    ]
    writer = csv.DictWriter(out, fieldnames=fieldnames)
    writer.writeheader()
    for r in sorted_records:
        writer.writerow(_record_to_dict(r))


# ── JSON output ───────────────────────────────────────────────────────────────

def report_json(
    records: list[CredRecord],
    top: Optional[int] = None,
    output=None,
) -> None:
    """Write newline-delimited JSON to stdout or a file-like object."""
    sorted_records = sorted(records, key=lambda r: r.risk_score, reverse=True)
    if top:
        sorted_records = sorted_records[:top]

    out = output or sys.stdout
    for r in sorted_records:
        out.write(json.dumps(_record_to_dict(r)) + "\n")


# ── Dispatcher ────────────────────────────────────────────────────────────────

def report(
    records: list[CredRecord],
    fmt: str = "table",
    target_domain: Optional[str] = None,
    top: Optional[int] = None,
) -> None:
    """
    Dispatch to the correct reporter based on fmt.

    Args:
        records:       List of scored CredRecords to report.
        fmt:           One of: table, csv, json.
        target_domain: Used as subtitle in table output.
        top:           Limit output to top N by risk_score.
    """
    if fmt == "table":
        report_table(records, target_domain=target_domain, top=top)
    elif fmt == "csv":
        report_csv(records, top=top)
    elif fmt == "json":
        report_json(records, top=top)
    else:
        console.print(f"[red]Unknown format '{fmt}'. Use: table, csv, json[/red]")


# ── Summary banner ────────────────────────────────────────────────────────────

def print_summary(
    records: list[CredRecord],
    stats: dict,
    target_domain: Optional[str] = None,
) -> None:
    """Print a summary banner after processing completes."""
    high   = sum(1 for r in records if r.risk_score >= 0.8)
    medium = sum(1 for r in records if 0.6 <= r.risk_score < 0.8)
    low    = sum(1 for r in records if r.risk_score < 0.6)

    console.print()
    console.rule("[bold]run summary[/bold]")
    if target_domain:
        console.print(f"  target domain : [bold]{target_domain}[/bold]")
    console.print(f"  processed     : {stats.get('total_processed', 0):,}")
    console.print(f"  unique        : {stats.get('unique', 0):,}")
    console.print(f"  duplicates    : {stats.get('duplicates', 0):,}")
    console.print()
    console.print(f"  [bold red]high risk[/bold red]   (≥0.8) : {high}")
    console.print(f"  [orange3]medium risk[/orange3] (≥0.6) : {medium}")
    console.print(f"  [dim]low risk[/dim]    (<0.6) : {low}")
    console.rule()
    console.print()