"""Tests for murasaki.models."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from murasaki.models import (
    AtomicTest,
    CalderaAbility,
    DetectionHypothesis,
    EmulationPlan,
    PlanRequest,
    PrioritizedTTP,
    ThreatActor,
)


def test_atomic_test_required_fields() -> None:
    test = AtomicTest(
        guid="abc-123", name="My Test", platforms=["windows"], executor_type="powershell"
    )  # noqa: E501
    assert test.guid == "abc-123"
    assert test.description == ""


def test_prioritized_ttp_score_bounds() -> None:
    with pytest.raises(ValidationError):
        PrioritizedTTP(
            technique_id="T1059",
            technique_name="Command Scripting",
            tactic="execution",
            likelihood_score=6,  # out of range
            impact_score=3,
            rationale="test",
        )


def test_prioritized_ttp_score_lower_bound() -> None:
    with pytest.raises(ValidationError):
        PrioritizedTTP(
            technique_id="T1059",
            technique_name="Command Scripting",
            tactic="execution",
            likelihood_score=0,  # out of range
            impact_score=3,
            rationale="test",
        )


def test_detection_hypothesis_platform_literal() -> None:
    with pytest.raises(ValidationError):
        DetectionHypothesis(
            platform="elastic",  # type: ignore[arg-type]
            title="Test",
            query_or_description="some query",
        )


def test_emulation_plan_defaults() -> None:
    plan = EmulationPlan(
        title="Test Plan",
        vertical="healthcare",
        executive_summary="Summary here",
    )
    assert plan.threat_actors == []
    assert plan.attack_chain == []
    assert plan.generated_at is not None


def test_plan_request_top_n_bounds() -> None:
    with pytest.raises(ValidationError):
        PlanRequest(
            vertical="finance",
            asset_profile=["AD"],
            platforms=["Windows"],
            top_n=51,  # exceeds max
            output_dir=Path("/tmp/out"),
            formats=["markdown"],
        )


def test_full_emulation_plan_roundtrip() -> None:
    plan = EmulationPlan(
        title="FIN7 Emulation",
        vertical="financial services",
        asset_profile=["Active Directory", "SWIFT"],
        target_platforms=["Windows"],
        executive_summary="This plan emulates FIN7 TTPs.",
        threat_actors=[
            ThreatActor(
                group_id="G0046",
                name="FIN7",
                aliases=["Carbanak"],
                relevance_rationale="Targets financial institutions.",
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
                rationale="Widely used by FIN7.",
                atomic_tests=[
                    AtomicTest(
                        guid="f7e6ec05-c19e-4a80-b7c9-0d6a0dc6a23f",
                        name="Mimikatz",
                        platforms=["windows"],
                        executor_type="powershell",
                    )
                ],
                caldera_abilities=[
                    CalderaAbility(
                        ability_id="123e4567-e89b-12d3-a456-426614174000",
                        name="Run PowerShell Script",
                        tactic="execution",
                        platforms=["windows"],
                    )
                ],
                detections=[
                    DetectionHypothesis(
                        platform="splunk",
                        title="PowerShell Execution",
                        query_or_description='index=wineventlog EventCode=4104 ScriptBlockText="*"',
                        data_sources=["Windows Event Log"],
                    ),
                    DetectionHypothesis(
                        platform="generic",
                        title="PowerShell Execution",
                        query_or_description="Look for encoded commands in PowerShell logs.",
                        data_sources=["Windows Event Log"],
                    ),
                ],
            )
        ],
    )
    dumped = plan.model_dump()
    restored = EmulationPlan.model_validate(dumped)
    assert restored.title == plan.title
    assert len(restored.attack_chain) == 1
    assert restored.attack_chain[0].technique_id == "T1059.001"
