"""Tests for murasaki.agent — uses mocked Bedrock responses."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from murasaki.agent import AgentLoopError, _extract_emulation_plan, _handle_tool_use
from murasaki.models import EmulationPlan

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_PLAN_JSON = json.dumps(
    {
        "title": "Test Plan",
        "generated_at": "2026-04-01T12:00:00",
        "vertical": "financial services",
        "asset_profile": ["Active Directory"],
        "target_platforms": ["Windows"],
        "threat_actors": [
            {
                "group_id": "G0046",
                "name": "FIN7",
                "aliases": ["Carbanak"],
                "relevance_rationale": "Targets financial institutions.",
            }
        ],
        "attack_chain": [
            {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactic": "execution",
                "platforms": ["Windows"],
                "likelihood_score": 5,
                "impact_score": 4,
                "rationale": "FIN7 uses PowerShell heavily.",
                "atomic_tests": [],
                "caldera_abilities": [],
                "detections": [
                    {
                        "platform": "splunk",
                        "title": "PowerShell Detection",
                        "query_or_description": "index=wineventlog EventCode=4104",
                        "data_sources": ["Windows Event Log"],
                    }
                ],
            }
        ],
        "executive_summary": "Summary",
        "methodology_notes": "Notes",
    }
)


def _make_end_turn_response(text: str) -> dict:
    return {
        "stopReason": "end_turn",
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": text}],
            }
        },
    }


def _make_tool_use_response(tool_name: str, tool_input: dict, tool_use_id: str = "tu-1") -> dict:
    return {
        "stopReason": "tool_use",
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "toolUse",
                        "toolUseId": tool_use_id,
                        "name": tool_name,
                        "input": tool_input,
                    }  # noqa: E501
                ],
            }
        },
    }


# ---------------------------------------------------------------------------
# _extract_emulation_plan tests
# ---------------------------------------------------------------------------


def test_extract_plan_from_fenced_block() -> None:
    message = {
        "content": [
            {"type": "text", "text": f"Here is your plan:\n```json\n{_VALID_PLAN_JSON}\n```"}
        ]  # noqa: E501
    }
    plan = _extract_emulation_plan(message)
    assert isinstance(plan, EmulationPlan)
    assert plan.vertical == "financial services"
    assert plan.attack_chain[0].technique_id == "T1059.001"


def test_extract_plan_from_bare_json() -> None:
    message = {"content": [{"type": "text", "text": _VALID_PLAN_JSON}]}
    plan = _extract_emulation_plan(message)
    assert plan.title == "Test Plan"


def test_extract_plan_invalid_json_raises() -> None:
    message = {"content": [{"type": "text", "text": "```json\n{not valid json}\n```"}]}
    with pytest.raises(AgentLoopError, match="Failed to parse"):
        _extract_emulation_plan(message)


def test_extract_plan_no_json_raises() -> None:
    message = {"content": [{"type": "text", "text": "I couldn't find anything relevant."}]}
    with pytest.raises(AgentLoopError, match="did not produce"):
        _extract_emulation_plan(message)


def test_extract_plan_validation_failure_raises() -> None:
    bad_plan = json.dumps({"title": "Bad", "vertical": "x"})  # missing required fields
    message = {"content": [{"type": "text", "text": f"```json\n{bad_plan}\n```"}]}
    with pytest.raises(AgentLoopError, match="validation failed"):
        _extract_emulation_plan(message)


# ---------------------------------------------------------------------------
# _handle_tool_use tests
# ---------------------------------------------------------------------------


def test_handle_tool_use_dispatches_correctly() -> None:
    message = {
        "content": [
            {
                "type": "toolUse",
                "toolUseId": "tu-abc",
                "name": "get_technique_detail",
                "input": {"technique_id": "T1059.001"},
            }
        ]
    }
    with patch("murasaki.tools.registry.attack_loader.get_technique_detail") as mock_detail:
        mock_detail.return_value = {"technique_id": "T1059.001", "name": "PowerShell"}
        result = _handle_tool_use(message, no_cache=False)

    assert result["role"] == "user"
    assert len(result["content"]) == 1
    assert result["content"][0]["toolUseId"] == "tu-abc"
    assert result["content"][0]["type"] == "toolResult"


def test_handle_tool_use_unknown_tool() -> None:
    message = {
        "content": [
            {"type": "toolUse", "toolUseId": "tu-x", "name": "nonexistent_tool", "input": {}}
        ]
    }
    result = _handle_tool_use(message, no_cache=False)
    content = result["content"][0]["content"][0]["json"]
    assert "error" in content


def test_handle_tool_use_ignores_non_tool_blocks() -> None:
    message = {
        "content": [
            {"type": "text", "text": "thinking..."},
            {
                "type": "toolUse",
                "toolUseId": "tu-1",
                "name": "get_technique_detail",
                "input": {"technique_id": "T1059"},
            },  # noqa: E501
        ]
    }
    with patch("murasaki.tools.registry.attack_loader.get_technique_detail") as mock_detail:
        mock_detail.return_value = {"technique_id": "T1059", "name": "Test"}
        result = _handle_tool_use(message, no_cache=False)
    # Only one toolResult block, not two
    assert len(result["content"]) == 1


# ---------------------------------------------------------------------------
# Full agent.run integration test (mocked Bedrock)
# ---------------------------------------------------------------------------


def test_agent_run_end_turn_immediately(tmp_path: Path) -> None:
    """Agent should return a plan when Bedrock immediately returns end_turn with valid JSON."""
    from murasaki.agent import run
    from murasaki.models import PlanRequest

    request = PlanRequest(
        vertical="financial services",
        asset_profile=["Active Directory"],
        platforms=["Windows"],
        top_n=5,
        output_dir=tmp_path,
        formats=["markdown"],
        aws_region="us-east-1",
    )

    mock_client = MagicMock()
    mock_client.converse.return_value = _make_end_turn_response(
        f"Here is the plan:\n```json\n{_VALID_PLAN_JSON}\n```"
    )

    with patch("boto3.Session") as mock_session:
        mock_session.return_value.client.return_value = mock_client
        plan = run(request)

    assert isinstance(plan, EmulationPlan)
    assert plan.vertical == "financial services"


def test_agent_run_exceeds_max_iterations(tmp_path: Path) -> None:
    """Agent should raise AgentLoopError if Bedrock never returns end_turn."""
    from murasaki.agent import _MAX_ITERATIONS, run
    from murasaki.models import PlanRequest

    request = PlanRequest(
        vertical="healthcare",
        asset_profile=["EHR"],
        platforms=["Windows"],
        top_n=5,
        output_dir=tmp_path,
        formats=["markdown"],
        aws_region="us-east-1",
    )

    # Always return a tool_use response — loop never ends
    mock_client = MagicMock()
    mock_client.converse.return_value = _make_tool_use_response(
        "get_technique_detail", {"technique_id": "T1059"}
    )

    with (
        patch("boto3.Session") as mock_session,
        patch("murasaki.tools.registry.attack_loader.get_technique_detail") as mock_detail,
    ):
        mock_session.return_value.client.return_value = mock_client
        mock_detail.return_value = {"technique_id": "T1059", "name": "Test"}
        with pytest.raises(AgentLoopError, match="exceeded"):
            run(request)

    assert mock_client.converse.call_count == _MAX_ITERATIONS


# ---------------------------------------------------------------------------
# Anthropic backend path
# ---------------------------------------------------------------------------


def test_agent_run_anthropic_backend(tmp_path: Path) -> None:
    """Agent should use AnthropicBackend when api_key is provided."""
    from murasaki.agent import run
    from murasaki.models import PlanRequest

    request = PlanRequest(
        vertical="financial services",
        asset_profile=["Active Directory"],
        platforms=["Windows"],
        top_n=5,
        output_dir=tmp_path,
        formats=["markdown"],
        aws_region="us-east-1",
        api_key="sk-ant-test-key",
    )

    # Build a mock Anthropic response that mimics the SDK's response object
    mock_content_block = MagicMock()
    mock_content_block.type = "text"
    mock_content_block.text = f"Here is the plan:\n```json\n{_VALID_PLAN_JSON}\n```"

    mock_response = MagicMock()
    mock_response.stop_reason = "end_turn"
    mock_response.content = [mock_content_block]

    mock_anthropic_client = MagicMock()
    mock_anthropic_client.messages.create.return_value = mock_response

    with patch("anthropic.Anthropic", return_value=mock_anthropic_client):
        plan = run(request)

    assert isinstance(plan, EmulationPlan)
    assert plan.vertical == "financial services"
    # Ensure Anthropic SDK was called, not boto3
    mock_anthropic_client.messages.create.assert_called_once()


def test_format_translation_roundtrip() -> None:
    """Bedrock tool-use message should round-trip through Anthropic format correctly."""
    from murasaki.agent import _bedrock_msg_to_anthropic

    bedrock_msg = {
        "role": "assistant",
        "content": [
            {"type": "text", "text": "Thinking..."},
            {
                "type": "toolUse",
                "toolUseId": "tu-123",
                "name": "get_technique_detail",
                "input": {"technique_id": "T1059"},
            },
        ],
    }

    anthropic_msg = _bedrock_msg_to_anthropic(bedrock_msg)
    assert anthropic_msg["role"] == "assistant"
    tool_block = next(b for b in anthropic_msg["content"] if b["type"] == "tool_use")
    assert tool_block["id"] == "tu-123"
    assert tool_block["name"] == "get_technique_detail"
    assert tool_block["input"] == {"technique_id": "T1059"}


def test_toolresult_translation() -> None:
    """Bedrock toolResult message should translate tool_use_id correctly for Anthropic."""
    from murasaki.agent import _bedrock_msg_to_anthropic

    bedrock_result_msg = {
        "role": "user",
        "content": [
            {
                "type": "toolResult",
                "toolUseId": "tu-abc",
                "content": [{"json": {"technique_id": "T1059", "name": "PowerShell"}}],
            }
        ],
    }

    anthropic_msg = _bedrock_msg_to_anthropic(bedrock_result_msg)
    result_block = anthropic_msg["content"][0]
    assert result_block["type"] == "tool_result"
    assert result_block["tool_use_id"] == "tu-abc"
    assert "T1059" in result_block["content"]
