import typer
from rich.console import Console
from pathlib import Path
from typing import Optional

app = typer.Typer(
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
        help="Target domain to filter results (e.g. example.com).",
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
):
    """
    Ingest a credential dump, normalize records, enrich via HIBP,
    and output prioritized hits for a target domain.
    """
    console.print(f"[bold green]credsift[/bold green] v0.1.0")
    console.print(f"  input:  {input_file}")
    console.print(f"  domain: {domain or 'all'}")
    console.print(f"  format: {output_format}")
    console.print(f"  top:    {top or 'all'}")
    console.print(f"  dry run: {dry_run}")
    console.print()
    console.print("[yellow]Pipeline not yet implemented — scaffold complete.[/yellow]")

if __name__ == "__main__":
    app()