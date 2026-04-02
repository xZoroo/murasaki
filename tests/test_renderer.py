"""Tests for murasaki.renderer."""

from datetime import datetime
from pathlib import Path

from murasaki.models import (
    AtomicTest,
    CalderaAbility,
    DetectionHypothesis,
    EmulationPlan,
    PrioritizedTTP,
    ThreatActor,
)
from murasaki.renderer import render


def _make_plan() -> EmulationPlan:
    return EmulationPlan(
        title="Test Purple Team Plan",
        generated_at=datetime(2026, 4, 1, 12, 0, 0),
        vertical="financial services",
        asset_profile=["Active Directory", "SWIFT"],
        target_platforms=["Windows"],
        executive_summary="This is a test executive summary.",
        threat_actors=[
            ThreatActor(
                group_id="G0046",
                name="FIN7",
                aliases=["Carbanak"],
                relevance_rationale="Known to target financial sector.",
            )
        ],
        attack_chain=[
            PrioritizedTTP(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="execution",
                platforms=["Windows"],
                likelihood_score=5,
                impact_score=4,
                rationale="Commonly used by FIN7 for execution.",
                atomic_tests=[
                    AtomicTest(
                        guid="f7e6ec05-c19e-4a80-b7c9-0d6a0dc6a23f",
                        name="Run Encoded PowerShell",
                        platforms=["windows"],
                        executor_type="powershell",
                    )
                ],
                caldera_abilities=[
                    CalderaAbility(
                        ability_id="123e4567-e89b-12d3-a456-426614174000",
                        name="PowerShell Download",
                        tactic="execution",
                        platforms=["windows"],
                    )
                ],
                detections=[
                    DetectionHypothesis(
                        platform="splunk",
                        title="PowerShell Execution via ScriptBlock",
                        query_or_description="index=wineventlog EventCode=4104",
                        data_sources=["Windows Event Log"],
                    ),
                    DetectionHypothesis(
                        platform="generic",
                        title="PowerShell Suspicious Execution",
                        query_or_description="Monitor for encoded PowerShell commands.",
                        data_sources=["Windows Event Log"],
                    ),
                ],
            )
        ],
    )


def test_markdown_render(tmp_path: Path) -> None:
    plan = _make_plan()
    files = render(plan, tmp_path, ["markdown"])
    assert len(files) == 3  # .md + caldera yaml + art runner
    md_path = next(f for f in files if f.suffix == ".md")
    content = md_path.read_text()

    assert "Test Purple Team Plan" in content
    assert "T1059.001" in content
    assert "FIN7" in content
    assert "f7e6ec05-c19e-4a80-b7c9-0d6a0dc6a23f" in content
    assert "123e4567-e89b-12d3-a456-426614174000" in content
    assert "index=wineventlog" in content
    assert "executive summary" in content.lower()


def test_html_render(tmp_path: Path) -> None:
    plan = _make_plan()
    files = render(plan, tmp_path, ["html"])
    assert len(files) == 3  # .html + caldera yaml + art runner
    html_path = next(f for f in files if f.suffix == ".html")
    content = html_path.read_text()

    assert "<!DOCTYPE html>" in content
    assert "Test Purple Team Plan" in content
    assert "T1059.001" in content
    assert "attack.mitre.org" in content
    assert "f7e6ec05" in content
    # Dark mode CSS
    assert "prefers-color-scheme: dark" in content


def test_both_formats(tmp_path: Path) -> None:
    plan = _make_plan()
    files = render(plan, tmp_path, ["markdown", "html"])
    assert len(files) == 4  # .md + .html + caldera yaml + art runner
    suffixes = {f.suffix for f in files}
    assert ".md" in suffixes
    assert ".html" in suffixes
    assert ".yml" in suffixes
    assert ".ps1" in suffixes


def test_output_dir_created(tmp_path: Path) -> None:
    plan = _make_plan()
    nested = tmp_path / "a" / "b" / "c"
    render(plan, nested, ["markdown"])
    assert nested.exists()


def test_empty_atomic_and_caldera(tmp_path: Path) -> None:
    plan = _make_plan()
    plan.attack_chain[0].atomic_tests = []
    plan.attack_chain[0].caldera_abilities = []
    files = render(plan, tmp_path, ["markdown", "html"])
    md_content = next(f for f in files if f.suffix == ".md").read_text()
    assert "No Atomic Red Team tests" in md_content
    html_content = next(f for f in files if f.suffix == ".html").read_text()
    assert "No Caldera stockpile abilities" in html_content


def test_named_output_files(tmp_path: Path) -> None:
    plan = _make_plan()
    files = render(plan, tmp_path, ["markdown", "html"], name="BankofMarina Q2 2026")
    stems = {f.stem for f in files}
    # Spaces become hyphens; all files share the same sanitized stem
    assert any("BankofMarina-Q2-2026" in s for s in stems)
    names = {f.name for f in files}
    assert "BankofMarina-Q2-2026.md" in names
    assert "BankofMarina-Q2-2026.html" in names
    assert "BankofMarina-Q2-2026-caldera.yml" in names
    assert "BankofMarina-Q2-2026-art-runner.ps1" in names


def test_default_stem_when_no_name(tmp_path: Path) -> None:
    plan = _make_plan()
    files = render(plan, tmp_path, ["markdown"])
    assert any(f.name == "murasaki-report.md" for f in files)


def test_caldera_yaml_content(tmp_path: Path) -> None:
    plan = _make_plan()
    files = render(plan, tmp_path, ["markdown"])
    caldera_file = next(f for f in files if f.suffix == ".yml")
    content = caldera_file.read_text()

    assert "atomic_ordering:" in content
    assert "123e4567-e89b-12d3-a456-426614174000" in content
    assert "name:" in content
    assert "id:" in content


def test_art_runner_content(tmp_path: Path) -> None:
    plan = _make_plan()
    files = render(plan, tmp_path, ["markdown"])
    art_file = next(f for f in files if f.suffix == ".ps1")
    content = art_file.read_text()

    assert "Import-Module invoke-atomicredteam" in content
    assert "Invoke-AtomicTest T1059.001" in content
    assert "f7e6ec05-c19e-4a80-b7c9-0d6a0dc6a23f" in content


def test_art_runner_no_guids(tmp_path: Path) -> None:
    """When no atomic GUIDs exist, Invoke-AtomicTest is called without -TestGuids."""
    plan = _make_plan()
    plan.attack_chain[0].atomic_tests = []
    files = render(plan, tmp_path, ["markdown"])
    art_file = next(f for f in files if f.suffix == ".ps1")
    content = art_file.read_text()

    assert "Invoke-AtomicTest T1059.001\n" in content
    assert "-TestGuids" not in content
