"""murasaki CLI entry point."""

import sys
from pathlib import Path
from typing import Literal

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from murasaki import agent, renderer
from murasaki.models import PlanRequest

console = Console()

_VERTICAL_EXAMPLES = (
    "financial services | healthcare | energy | retail | "
    "manufacturing | government | technology | education"
)

_PLATFORM_EXAMPLES = "Windows | Linux | macOS"

_CONTEXT = {"help_option_names": ["-h", "--help"], "max_content_width": 100}


@click.command(
    context_settings=_CONTEXT,
    epilog=(
        "Examples:\n\n"
        "  murasaki --vertical 'financial services' --assets 'Active Directory,SWIFT,AWS'\n\n"
        "  murasaki --vertical healthcare --assets 'Epic EHR,Active Directory' --top-n 20 --verbose\n\n"  # noqa: E501
        "  murasaki --api-key sk-ant-... --vertical energy --assets 'SCADA,Historian'\n\n"
        "  murasaki --aws-profile security-team --vertical retail --assets 'POS,Azure AD'"
    ),
)
@click.option(
    "--vertical",
    default=None,
    metavar="TEXT",
    help=(f"[REQUIRED] Industry vertical to target.\n\nAccepted values: {_VERTICAL_EXAMPLES}"),
)
@click.option(
    "--assets",
    default=None,
    metavar="TEXT",
    help=(
        "[REQUIRED] Comma-separated list of key assets in your environment.\n\n"
        "Example: 'Active Directory,SWIFT,Bloomberg Terminal,AWS S3'"
    ),
)
@click.option(
    "--platforms",
    default="Windows,Linux",
    show_default=True,
    metavar="TEXT",
    help=(f"Comma-separated target OS platforms.\n\nAccepted values: {_PLATFORM_EXAMPLES}"),
)
@click.option(
    "--top-n",
    default=15,
    show_default=True,
    type=click.IntRange(1, 50),
    metavar="1-50",
    help="Number of TTPs to prioritize and include in the emulation plan.",
)
@click.option(
    "--output-dir",
    default="./murasaki-output",
    show_default=True,
    type=click.Path(),
    metavar="PATH",
    help="Directory where reports are written. Created if it does not exist.",
)
@click.option(
    "--format",
    "fmt",
    default="both",
    show_default=True,
    type=click.Choice(["markdown", "html", "both"], case_sensitive=False),
    help="Output report format.",
)
@click.option(
    "--api-key",
    envvar="MURASAKI_API_KEY",
    default=None,
    metavar="TEXT",
    help=(
        "Anthropic API key. Calls api.anthropic.com directly — no AWS credentials needed.\n\n"
        "Can also be set via the MURASAKI_API_KEY environment variable.\n\n"
        "Conflicts with: --aws-profile, --aws-region"
    ),
)
@click.option(
    "--aws-region",
    default="us-east-1",
    show_default=True,
    metavar="TEXT",
    help="AWS region for Bedrock. Ignored when --api-key is set.",
)
@click.option(
    "--aws-profile",
    default=None,
    metavar="TEXT",
    help=(
        "AWS named profile. Uses the default credential chain if omitted.\n\n"
        "Conflicts with: --api-key"
    ),
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Bypass local disk cache and re-fetch Atomic Red Team and Caldera data from GitHub.",
)
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    help="Print each agent reasoning turn to the console.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    vertical: str | None,
    assets: str | None,
    platforms: str,
    top_n: int,
    output_dir: str,
    fmt: str,
    api_key: str | None,
    aws_region: str,
    aws_profile: str | None,
    no_cache: bool,
    verbose: bool,
) -> None:
    """murasaki — purple team TTP prioritization and adversary emulation planner.

    Identifies the threat actors most likely to target your industry, prioritizes
    ATT&CK TTPs by likelihood and impact, and generates a full adversary emulation
    plan with Atomic Red Team test GUIDs, Caldera ability IDs, and detection hypotheses.
    """
    # Show help when invoked with no arguments
    if vertical is None and assets is None:
        click.echo(ctx.get_help())
        sys.exit(0)

    # Validate required fields
    missing = []
    if not vertical:
        missing.append("--vertical")
    if not assets:
        missing.append("--assets")
    if missing:
        raise click.UsageError(f"Missing required option(s): {', '.join(missing)}")

    # Conflict detection: --api-key is mutually exclusive with AWS flags
    if api_key and aws_profile:
        raise click.UsageError(
            "--api-key and --aws-profile cannot be used together.\n"
            "  --api-key  → calls api.anthropic.com directly (no AWS needed)\n"
            "  --aws-profile → uses AWS Bedrock with IAM credentials\n"
            "Pick one authentication method."
        )

    asset_profile = [a.strip() for a in assets.split(",") if a.strip()]
    platform_list = [p.strip() for p in platforms.split(",") if p.strip()]
    formats: list[Literal["markdown", "html"]] = (
        ["markdown", "html"] if fmt == "both" else [fmt]  # type: ignore[list-item]
    )
    backend_label = "Anthropic API" if api_key else f"AWS Bedrock ({aws_region})"

    request = PlanRequest(
        vertical=vertical,
        asset_profile=asset_profile,
        platforms=platform_list,
        top_n=top_n,
        output_dir=Path(output_dir),
        formats=formats,
        aws_region=aws_region,
        aws_profile=aws_profile,
        api_key=api_key,
        no_cache=no_cache,
        verbose=verbose,
    )

    console.print(
        Panel.fit(
            f"[bold]murasaki[/bold] — adversary emulation planner\n"
            f"Vertical: [cyan]{vertical}[/cyan]  |  "
            f"Assets: [cyan]{assets}[/cyan]  |  "
            f"Top TTPs: [cyan]{top_n}[/cyan]  |  "
            f"Backend: [cyan]{backend_label}[/cyan]",
            border_style="red",
        )
    )

    def progress_callback(turn: int, content: str) -> None:
        if verbose:
            console.print(f"\n[dim]--- Turn {turn} ---[/dim]")
            console.print(f"[dim]{content}[/dim]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=not verbose,
    ) as progress:
        task_id = progress.add_task("Running agentic loop…", total=None)

        try:
            emulation_plan = agent.run(request, progress_callback=progress_callback)
        except agent.AgentLoopError as exc:
            console.print(f"\n[bold red]Agent error:[/bold red] {exc}")
            raise SystemExit(1) from exc
        except Exception as exc:
            console.print(f"\n[bold red]Unexpected error:[/bold red] {exc}")
            raise SystemExit(1) from exc

        progress.update(task_id, description="Rendering reports…")
        output_files = renderer.render(emulation_plan, request.output_dir, request.formats)

    console.print("\n[bold green]Done![/bold green] Reports generated:")
    for path in output_files:
        console.print(f"  [cyan]{path}[/cyan]")
