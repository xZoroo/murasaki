"""Pydantic data models for murasaki."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class AtomicTest(BaseModel):
    """A single Atomic Red Team test entry."""

    guid: str
    name: str
    platforms: list[str]
    executor_type: str
    description: str = ""


class CalderaAbility(BaseModel):
    """A Caldera stockpile ability mapped to an ATT&CK technique."""

    ability_id: str
    name: str
    tactic: str
    platforms: list[str]
    description: str = ""


class DetectionHypothesis(BaseModel):
    """A detection hypothesis for a TTP, either as a Splunk query or generic description."""

    platform: Literal["splunk", "generic"]
    title: str
    query_or_description: str
    data_sources: list[str] = Field(default_factory=list)


class PrioritizedTTP(BaseModel):
    """A single ATT&CK technique prioritized for purple team testing."""

    technique_id: str
    technique_name: str
    tactic: str
    platforms: list[str] = Field(default_factory=list)
    likelihood_score: int = Field(ge=1, le=5)
    impact_score: int = Field(ge=1, le=5)
    rationale: str
    atomic_tests: list[AtomicTest] = Field(default_factory=list)
    caldera_abilities: list[CalderaAbility] = Field(default_factory=list)
    detections: list[DetectionHypothesis] = Field(default_factory=list)


class ThreatActor(BaseModel):
    """An ATT&CK threat actor group relevant to the target vertical."""

    group_id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    relevance_rationale: str


class EmulationPlan(BaseModel):
    """A complete adversary emulation plan produced by the agent."""

    title: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    vertical: str
    asset_profile: list[str] = Field(default_factory=list)
    target_platforms: list[str] = Field(default_factory=list)
    threat_actors: list[ThreatActor] = Field(default_factory=list)
    attack_chain: list[PrioritizedTTP] = Field(default_factory=list)
    executive_summary: str
    methodology_notes: str = ""


class PlanRequest(BaseModel):
    """Input parameters for the murasaki plan command."""

    vertical: str
    asset_profile: list[str]
    platforms: list[str]
    top_n: int = Field(default=15, ge=1, le=50)
    output_dir: Path
    formats: list[Literal["markdown", "html"]]
    aws_region: str = "us-east-1"
    aws_profile: str | None = None
    api_key: str | None = None
    no_cache: bool = False
    verbose: bool = False
