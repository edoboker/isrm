"""Command-line interface for isrm."""

from __future__ import annotations

import logging
import sys

import click

from isrm.assess.collectors.threat_history import collect_threat_history
from isrm.assess.pipeline import run_assessment
from isrm.assess.report import render_json, render_terminal
from isrm.config import load_settings

logger = logging.getLogger(__name__)


def _configure_logging(verbose: bool) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


@click.group()
def main() -> None:
    """Internet service risk manager."""


@main.command()
@click.argument("url")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output report as JSON.")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable debug logging.")
def assess(url: str, as_json: bool, verbose: bool) -> None:
    """Assess the risk of connecting to a URL."""
    _configure_logging(verbose)

    try:
        settings = load_settings()
    except Exception as exc:
        click.echo(f"Configuration error: {exc}", err=True)
        sys.exit(1)

    logger.info("Starting assessment for %s", url)

    try:
        report = run_assessment(url, settings)
    except ValueError as exc:
        click.echo(f"Invalid target: {exc}", err=True)
        sys.exit(1)
    except Exception as exc:
        logger.debug("Unexpected error", exc_info=True)
        click.echo(f"Assessment failed: {exc}", err=True)
        sys.exit(1)

    if as_json:
        click.echo(render_json(report))
    else:
        render_terminal(report)


@main.command("research-threat-history")
@click.argument("target")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Enable debug logging.")
def research_threat_history(target: str, verbose: bool) -> None:
    """Research public threat history for a hostname or URL."""
    _configure_logging(verbose)

    try:
        settings = load_settings()
    except Exception as exc:
        click.echo(f"Configuration error: {exc}", err=True)
        sys.exit(1)

    logger.info("Researching threat history for %s", target)

    try:
        result = collect_threat_history(target, settings)
    except Exception as exc:
        logger.debug("Unexpected error", exc_info=True)
        click.echo(f"Research failed: {exc}", err=True)
        sys.exit(1)

    click.echo(result.model_dump_json(indent=2))
