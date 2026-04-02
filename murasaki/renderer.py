"""Markdown and HTML report renderer for murasaki.

Renders an EmulationPlan to Markdown and/or HTML using Jinja2 templates.
The HTML report is self-contained with inline CSS supporting dark/light mode.

Also produces a Caldera adversary YAML (importable via the Caldera UI) and
an Atomic Red Team PowerShell runner script for each plan.
"""

import logging
import re
import uuid
from pathlib import Path

import markdown as md_lib
from jinja2 import Environment, FileSystemLoader

from murasaki.models import EmulationPlan

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def render(
    plan: EmulationPlan,
    output_dir: Path,
    formats: list[str],
    name: str | None = None,
) -> list[Path]:
    """Render *plan* to the requested *formats* in *output_dir*.

    Always generates a Caldera adversary YAML and ART PowerShell runner
    in addition to the requested report formats.

    Args:
        plan: The completed EmulationPlan to render.
        output_dir: Directory where report files will be written. Created if absent.
        formats: List of format strings — "markdown" and/or "html".
        name: Optional engagement name used as the output file stem.

    Returns:
        List of Paths to all generated files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = _file_stem(name)

    # HTML env: autoescape=True ensures all template variables are HTML-escaped.
    # The template also applies | e filters explicitly as defence-in-depth.
    # Note: select_autoescape(["html"]) would NOT apply here because our template
    # is named report.html.j2 (.j2 extension), so we set autoescape=True directly.
    html_env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    html_env.filters["markdown_to_html"] = _markdown_to_html

    # Markdown env: autoescape is intentionally disabled. The output is a .md file,
    # not rendered HTML, so HTML escaping would corrupt the Markdown syntax.
    # Plan data written here does not flow into any HTML context.
    md_env = Environment(  # nosec B701 — Markdown output, not HTML
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    md_env.filters["markdown_to_html"] = _markdown_to_html

    plan_dict = plan.model_dump()
    plan_dict["generated_at_str"] = plan.generated_at.strftime("%Y-%m-%d %H:%M UTC")

    generated: list[Path] = []

    if "markdown" in formats:
        md_content = md_env.get_template("report.md.j2").render(plan=plan_dict)
        md_path = output_dir / f"{stem}.md"
        # output_dir is the user's chosen report destination — path is not attacker-controlled
        md_path.write_text(md_content, encoding="utf-8")  # nosec B102
        generated.append(md_path)
        logger.info("Markdown report written to %s", md_path)

    if "html" in formats:
        html_content = html_env.get_template("report.html.j2").render(plan=plan_dict)
        html_path = output_dir / f"{stem}.html"
        # output_dir is the user's chosen report destination — path is not attacker-controlled
        html_path.write_text(html_content, encoding="utf-8")  # nosec B102
        generated.append(html_path)
        logger.info("HTML report written to %s", html_path)

    caldera_path = output_dir / f"{stem}-caldera.yml"
    # stem is sanitized by _file_stem(); output_dir is user-chosen — not attacker-controlled
    caldera_path.write_text(_render_caldera_adversary(plan), encoding="utf-8")  # nosec B102
    generated.append(caldera_path)
    logger.info("Caldera adversary profile written to %s", caldera_path)

    art_path = output_dir / f"{stem}-art-runner.ps1"
    # stem is sanitized by _file_stem(); output_dir is user-chosen — not attacker-controlled
    art_path.write_text(_render_art_runner(plan, stem), encoding="utf-8")  # nosec B102
    generated.append(art_path)
    logger.info("Atomic Red Team runner written to %s", art_path)

    return generated


def _file_stem(name: str | None) -> str:
    """Return a filesystem-safe stem from an engagement name, or a sensible default."""
    if not name:
        return "murasaki-report"
    safe = re.sub(r"[^\w\-]", "-", name).strip("-")
    safe = re.sub(r"-{2,}", "-", safe)
    return safe or "murasaki-report"


def _render_caldera_adversary(plan: EmulationPlan) -> str:
    """Build a Caldera adversary YAML importable via the Caldera UI (Adversaries > Import).

    The file lists every Caldera ability ID found across the attack chain,
    de-duplicated and ordered by technique appearance.
    """
    ability_ids: list[str] = []
    seen: set[str] = set()
    for ttp in plan.attack_chain:
        for ability in ttp.caldera_abilities:
            if ability.ability_id not in seen:
                ability_ids.append(ability.ability_id)
                seen.add(ability.ability_id)

    profile_id = str(uuid.uuid4())
    date_str = plan.generated_at.strftime("%Y-%m-%d")
    lines = [
        f"id: {profile_id}",
        f"name: {plan.title}",
        f"description: 'Generated by murasaki on {date_str}. "
        f"Vertical: {plan.vertical}. "
        f"Threat actors: {', '.join(a.name for a in plan.threat_actors)}.'",
        "atomic_ordering:",
    ]
    if ability_ids:
        lines.extend(f"- {aid}" for aid in ability_ids)
    else:
        lines.append("[]  # No Caldera abilities were mapped for this plan")

    return "\n".join(lines) + "\n"


def _render_art_runner(plan: EmulationPlan, stem: str) -> str:
    """Build an Invoke-AtomicRedTeam PowerShell runner script.

    Each technique in the attack chain gets an Invoke-AtomicTest call.
    When specific test GUIDs are available they are passed via -TestGuids;
    otherwise the call runs all tests for that technique.
    """
    date_str = plan.generated_at.strftime("%Y-%m-%d")
    actors = ", ".join(a.name for a in plan.threat_actors) or "N/A"

    header = f"""\
<#
.SYNOPSIS
    Atomic Red Team emulation runner — generated by murasaki

.DESCRIPTION
    Engagement : {stem}
    Vertical   : {plan.vertical}
    Actors     : {actors}
    Generated  : {date_str}

    Prerequisites:
        Install-Module -Name invoke-atomicredteam -Scope CurrentUser
        Install-Module -Name powershell-yaml -Scope CurrentUser

    Usage:
        .\\{stem}-art-runner.ps1

    Review each test before running in your environment. Some tests require
    elevated privileges or may cause system changes. Run in a lab environment
    or with proper change-control approval.
#>

Import-Module invoke-atomicredteam
"""

    blocks: list[str] = []
    for ttp in plan.attack_chain:
        guids = [t.guid for t in ttp.atomic_tests if t.guid]
        guid_arg = f' -TestGuids "{", ".join(guids)}"' if guids else ""
        block_lines = [
            f"# {ttp.technique_id} — {ttp.technique_name} ({ttp.tactic})"
            f"  [L:{ttp.likelihood_score} I:{ttp.impact_score}]",
            f"# {ttp.rationale}",
            f"Invoke-AtomicTest {ttp.technique_id}{guid_arg}",
            "",
        ]
        blocks.append("\n".join(block_lines))

    return header + "\n" + "\n".join(blocks)


def _markdown_to_html(text: str) -> str:
    """Jinja2 filter: convert Markdown text to HTML."""
    return md_lib.markdown(
        text,
        extensions=["tables", "fenced_code", "nl2br"],
    )
