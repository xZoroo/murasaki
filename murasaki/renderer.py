"""Markdown and HTML report renderer for murasaki.

Renders an EmulationPlan to Markdown and/or HTML using Jinja2 templates.
The HTML report is self-contained with inline CSS supporting dark/light mode.
"""

import logging
from pathlib import Path

import markdown as md_lib
from jinja2 import Environment, FileSystemLoader

from murasaki.models import EmulationPlan

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def render(plan: EmulationPlan, output_dir: Path, formats: list[str]) -> list[Path]:
    """Render *plan* to the requested *formats* in *output_dir*.

    Args:
        plan: The completed EmulationPlan to render.
        output_dir: Directory where report files will be written. Created if absent.
        formats: List of format strings — "markdown" and/or "html".

    Returns:
        List of Paths to the generated files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

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
        md_path = output_dir / "murasaki-report.md"
        # output_dir is the user's chosen report destination — path is not attacker-controlled
        md_path.write_text(md_content, encoding="utf-8")  # nosec B102
        generated.append(md_path)
        logger.info("Markdown report written to %s", md_path)

    if "html" in formats:
        html_content = html_env.get_template("report.html.j2").render(plan=plan_dict)
        html_path = output_dir / "murasaki-report.html"
        # output_dir is the user's chosen report destination — path is not attacker-controlled
        html_path.write_text(html_content, encoding="utf-8")  # nosec B102
        generated.append(html_path)
        logger.info("HTML report written to %s", html_path)

    return generated


def _markdown_to_html(text: str) -> str:
    """Jinja2 filter: convert Markdown text to HTML."""
    return md_lib.markdown(
        text,
        extensions=["tables", "fenced_code", "nl2br"],
    )
