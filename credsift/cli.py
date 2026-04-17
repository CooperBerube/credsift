# credsift/cli.py
"""
credsift — credential dump triage CLI.

Pipeline
--------
    1. Ingest   — read lines from input file
    2. Parse    — detect format, extract fields into CredRecord
    3. Dedupe   — bloom filter + SQLite dedup
    4. Score    — weighted risk scoring against target domain
    5. Enrich   — HIBP k-anonymity check (plaintext passwords only)
    6. Store    — write unique records to SQLite session DB
    7. Report   — table / CSV / JSON output
"""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from credsift.parsers import parse_line
from credsift.deduplicator import Deduplicator
from credsift.scorer import score_and_update, ScoringWeights
from credsift.enricher import init_hibp_cache, enrich
from credsift.db import init_db, insert_record
from credsift.reporter import report, print_summary

app     = typer.Typer(
    name="credsift",
    help="Triage and analyze credential dumps against a target domain.",
    add_completion=False,
)
console = Console()


@app.command()
def main(
    input_file: Path = typer.Option(
        ..., "--input", "-i",
        help="Path to credential dump file.",
        exists=True, readable=True,
    ),
    domain: Optional[str] = typer.Option(
        None, "--domain", "-d",
        help="Target domain to filter and prioritize (e.g. example.com).",
    ),
    output_format: str = typer.Option(
        "table", "--format", "-f",
        help="Output format: table, csv, or json.",
    ),
    top: Optional[int] = typer.Option(
        None, "--top",
        help="Show only the top N results by risk score.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Process input but do not write to database.",
    ),
    no_enrich: bool = typer.Option(
        False, "--no-enrich",
        help="Skip HIBP enrichment (faster, offline-safe).",
    ),
    db_path: Path = typer.Option(
        Path("credsift.db"), "--db",
        help="Path to SQLite session database.",
    ),
    source: Optional[str] = typer.Option(
        None, "--source",
        help="Label for this data source (e.g. 'rockyou', 'breach-2024').",
    ),
    min_score: float = typer.Option(
        0.0, "--min-score",
        help="Only show results at or above this risk score (0.0–1.0).",
    ),
):
    """
    Ingest a credential dump, normalize records, enrich via HIBP,
    and output prioritized hits for a target domain.
    """
    # ── Setup ─────────────────────────────────────────────────────────────────
    console.print(f"\n[bold green]credsift[/bold green]  starting run\n")

    if not dry_run:
        init_db(db_path)
        init_hibp_cache(db_path)

    dedup   = Deduplicator(db_path=db_path)
    results = []

    # ── Ingest → Parse → Dedupe → Score → Enrich → Store ─────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed} records"),
        console=console,
        transient=True,
    ) as progress:

        task = progress.add_task("processing...", total=None)

        with open(input_file, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue

                # 1. Parse
                record = parse_line(line)
                if record is None:
                    continue

                # 2. Tag source
                if source:
                    record.source = source

                # 3. Dedupe
                if not dedup.is_new(record):
                    continue

                # 4. Score
                score_and_update(record, target_domain=domain)

                # 5. Filter by min_score early to avoid enriching low-value records
                if record.risk_score < min_score:
                    continue

                # 6. Enrich
                if not no_enrich and not record.is_hash:
                    enrich(record, db_path=db_path)

                # 7. Store
                if not dry_run:
                    insert_record(record, db_path)

                results.append(record)
                progress.advance(task)

    # ── Report ────────────────────────────────────────────────────────────────
    if not results:
        console.print("[yellow]No records matched. Check your input file and flags.[/yellow]\n")
        raise typer.Exit(0)

    # Filter to domain if specified (show domain matches + unmatched for context)
    display = results
    if domain:
        domain_hits = [r for r in results if r.domain == domain]
        display     = domain_hits if domain_hits else results

    print_summary(display, dedup.stats, target_domain=domain)
    report(display, fmt=output_format, target_domain=domain, top=top)


if __name__ == "__main__":
    app()