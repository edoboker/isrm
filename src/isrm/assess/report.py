"""Report rendering: terminal (Rich) and JSON."""

from __future__ import annotations

import json

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from isrm.models import RiskLabel, RiskReport

console = Console()

_LABEL_STYLES: dict[RiskLabel, str] = {
    RiskLabel.LOW: "bold green",
    RiskLabel.MEDIUM: "bold yellow",
    RiskLabel.HIGH: "bold orange1",
    RiskLabel.CRITICAL: "bold red",
}


def render_terminal(report: RiskReport) -> None:
    """Render a RiskReport to the terminal using Rich.

    Args:
        report: The risk report to display.
    """
    style = _LABEL_STYLES.get(report.label, "bold white")

    # Header panel
    console.print(
        Panel(
            f"[bold]Target:[/bold] {report.target}\n"
            f"[bold]Score:[/bold]  [{style}]{report.score}/100 — {report.label.value}[/{style}]\n"
            f"[bold]Confidence:[/bold] {report.confidence}%",
            title="[bold]ISRM Risk Assessment[/bold]",
            border_style=style,
        )
    )

    # Rationale
    console.print(Panel(report.rationale, title="Rationale", border_style="dim"))

    # Findings table
    if report.findings:
        table = Table(title="Findings by Collector", box=box.SIMPLE_HEAVY, show_lines=True)
        table.add_column("Collector", style="bold")
        table.add_column("Score", justify="right")
        table.add_column("Confidence", justify="right")
        table.add_column("Data Gap", justify="center")
        table.add_column("Explanation")

        for finding in report.findings:
            gap_marker = "[yellow]YES[/yellow]" if finding.data_gap else "no"
            table.add_row(
                finding.collector,
                str(finding.score),
                f"{finding.confidence}%",
                gap_marker,
                finding.explanation,
            )
        console.print(table)

    # Data gaps
    if report.data_gaps:
        console.print("\n[bold yellow]Data Gaps[/bold yellow]")
        for gap in report.data_gaps:
            console.print(f"  [yellow]•[/yellow] {gap}")

    # Assumptions
    if report.assumptions:
        console.print("\n[bold dim]Assumptions[/bold dim]")
        for assumption in report.assumptions:
            console.print(f"  [dim]•[/dim] {assumption}")


def render_json(report: RiskReport) -> str:
    """Serialize a RiskReport to a JSON string.

    Args:
        report: The risk report to serialize.

    Returns:
        Indented JSON string.
    """
    return json.dumps(report.model_dump(mode="json"), indent=2)
