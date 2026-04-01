"""Bedrock agentic loop for murasaki.

Drives a stateful conversation with Claude via one of three backends:
  - AWS Bedrock API key  — Bearer token via AWS_BEARER_TOKEN_BEDROCK env var
  - Anthropic API key   — calls api.anthropic.com via MURASAKI_API_KEY / --api-key
  - AWS IAM credentials — boto3 SigV4 signing (access key, IAM role, SSO, etc.)

All backends normalise messages to Bedrock's internal format so the loop
logic is shared. The Anthropic backend translates on the way in and out.
"""

import json
import logging
import os
import re
from typing import Any, Protocol

import boto3
import httpx

from murasaki.models import EmulationPlan, PlanRequest
from murasaki.tools.registry import TOOL_SPECS, dispatch

logger = logging.getLogger(__name__)

_BEDROCK_MODEL_ID = "us.anthropic.claude-sonnet-4-6"
_ANTHROPIC_MODEL_ID = "claude-sonnet-4-6"
_MAX_ITERATIONS = 25

_SYSTEM_PROMPT = """You are an expert purple team security analyst. Your task is to:

1. PHASE 1 — TTP PRIORITIZATION:
   - Use get_groups_for_vertical to identify threat actor groups targeting the given industry.
   - Use get_techniques_for_group for the top 3-5 most relevant groups.
   - Use get_technique_detail on candidate techniques to understand data sources.
   - Reason about likelihood (how commonly this TTP is used against this vertical) and
     impact (how damaging it would be given the stated asset profile). Score 1-5 each.
   - Select the top N techniques as specified by the user.

2. PHASE 2 — EMULATION PLAN GENERATION:
   - For each selected technique, call get_atomic_tests to retrieve Atomic Red Team test GUIDs.
   - For each selected technique, call get_caldera_abilities to retrieve Caldera ability IDs.
   - Order the techniques into a realistic attack chain following the kill chain phases.
   - Write detection hypotheses: one Splunk SPL query and one generic/agnostic description per TTP.
     Ground the SPL queries in the data_sources returned by get_technique_detail.

CRITICAL RULES:
- NEVER fabricate technique IDs, Atomic Red Team GUIDs, or Caldera ability IDs.
  Only use values returned by the tools.
- Call tools as many times as needed — thoroughness is valued.
- When you have completed both phases, emit your final answer as a JSON code block
  that strictly conforms to the EmulationPlan schema below. Do not include any text
  after the JSON block.

EmulationPlan schema:
{
  "title": "string",
  "generated_at": "ISO8601 datetime",
  "vertical": "string",
  "asset_profile": ["string"],
  "target_platforms": ["string"],
  "threat_actors": [
    {"group_id": "G0XXX", "name": "string", "aliases": ["string"], "relevance_rationale": "string"}
  ],
  "attack_chain": [
    {
      "technique_id": "TXXXX.XXX",
      "technique_name": "string",
      "tactic": "string",
      "platforms": ["string"],
      "likelihood_score": 1-5,
      "impact_score": 1-5,
      "rationale": "string",
      "atomic_tests": [
        {"guid": "string", "name": "string", "platforms": ["string"],
         "executor_type": "string", "description": "string"}
      ],
      "caldera_abilities": [
        {"ability_id": "string", "name": "string", "tactic": "string",
         "platforms": ["string"], "description": "string"}
      ],
      "detections": [
        {"platform": "splunk", "title": "string", "query_or_description": "string",
         "data_sources": ["string"]},
        {"platform": "generic", "title": "string", "query_or_description": "string",
         "data_sources": ["string"]}
      ]
    }
  ],
  "executive_summary": "string",
  "methodology_notes": "string"
}
"""


class AgentLoopError(Exception):
    """Raised when the agentic loop exceeds max iterations or encounters a fatal error."""


# ---------------------------------------------------------------------------
# Backend protocol — both backends return (stop_reason, output_message)
# where output_message uses Bedrock's internal format.
# ---------------------------------------------------------------------------


class _LLMBackend(Protocol):
    def converse(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str,
        tool_specs: list[dict[str, Any]],
    ) -> tuple[str, dict[str, Any]]: ...


class _BedrockBackend:
    """Calls Claude via AWS Bedrock (boto3 converse API)."""

    def __init__(self, aws_region: str, aws_profile: str | None) -> None:
        session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
        self._client = session.client("bedrock-runtime")

    def converse(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str,
        tool_specs: list[dict[str, Any]],
    ) -> tuple[str, dict[str, Any]]:
        response = self._client.converse(
            modelId=_BEDROCK_MODEL_ID,
            system=[{"text": system_prompt}],
            messages=messages,
            toolConfig={"tools": tool_specs},
        )
        stop_reason: str = response.get("stopReason", "")
        output_message: dict[str, Any] = response.get("output", {}).get("message", {})
        return stop_reason, output_message


class _BedrockApiKeyBackend:
    """Calls Bedrock using an API key (Bearer token) via direct HTTPS.

    Reads the key from the AWS_BEARER_TOKEN_BEDROCK environment variable.
    No IAM signing required — the API key is passed as x-amzn-api-key header.
    """

    def __init__(self, api_key: str, aws_region: str) -> None:
        self._api_key = api_key
        self._base_url = f"https://bedrock-runtime.{aws_region}.amazonaws.com"

    def converse(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str,
        tool_specs: list[dict[str, Any]],
    ) -> tuple[str, dict[str, Any]]:
        url = f"{self._base_url}/model/{_BEDROCK_MODEL_ID}/converse"
        headers = {
            "Content-Type": "application/json",
            "x-amzn-api-key": self._api_key,
        }
        body: dict[str, Any] = {
            "system": [{"text": system_prompt}],
            "messages": messages,
            "toolConfig": {"tools": tool_specs},
        }
        try:
            with httpx.Client(timeout=120) as client:
                resp = client.post(url, json=body, headers=headers)
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise AgentLoopError(
                f"Bedrock API key request failed ({exc.response.status_code}): "
                f"{exc.response.text[:300]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise AgentLoopError(f"Bedrock API key request error: {exc}") from exc

        data: dict[str, Any] = resp.json()
        stop_reason: str = data.get("stopReason", "")
        output_message: dict[str, Any] = data.get("output", {}).get("message", {})
        return stop_reason, output_message


class _AnthropicBackend:
    """Calls Claude via the Anthropic API (api.anthropic.com) using an API key."""

    def __init__(self, api_key: str) -> None:
        import anthropic

        self._client = anthropic.Anthropic(api_key=api_key)

    def converse(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str,
        tool_specs: list[dict[str, Any]],
    ) -> tuple[str, dict[str, Any]]:
        import anthropic

        anthropic_messages = [_bedrock_msg_to_anthropic(m) for m in messages]
        anthropic_tools = [_bedrock_toolspec_to_anthropic(t) for t in tool_specs]

        try:
            response = self._client.messages.create(
                model=_ANTHROPIC_MODEL_ID,
                system=system_prompt,
                messages=anthropic_messages,
                tools=anthropic_tools,
                max_tokens=8192,
            )
        except anthropic.APIError as exc:
            raise AgentLoopError(f"Anthropic API error: {exc}") from exc

        stop_reason = "end_turn" if response.stop_reason == "end_turn" else "tool_use"
        output_message = _anthropic_response_to_bedrock(response)
        return stop_reason, output_message


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def run(request: PlanRequest, progress_callback: Any = None) -> EmulationPlan:
    """Run the full agentic loop and return a completed EmulationPlan.

    Args:
        request: The PlanRequest containing org profile and configuration.
        progress_callback: Optional callable(turn: int, content: str) called
            after each agent turn for display purposes.

    Returns:
        A validated EmulationPlan instance.

    Raises:
        AgentLoopError: If the loop exceeds _MAX_ITERATIONS or encounters an error.
    """
    bedrock_bearer = os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
    if bedrock_bearer:
        backend: _LLMBackend = _BedrockApiKeyBackend(bedrock_bearer, request.aws_region)
    elif request.api_key:
        backend = _AnthropicBackend(request.api_key)
    else:
        backend = _BedrockBackend(request.aws_region, request.aws_profile)

    user_message = _build_initial_message(request)
    messages: list[dict[str, Any]] = [{"role": "user", "content": user_message}]

    for iteration in range(_MAX_ITERATIONS):
        logger.debug("Agent iteration %d", iteration + 1)

        stop_reason, output_message = backend.converse(messages, _SYSTEM_PROMPT, TOOL_SPECS)
        messages.append(output_message)

        if progress_callback:
            _emit_progress(progress_callback, iteration + 1, output_message)

        if stop_reason == "end_turn":
            return _extract_emulation_plan(output_message)

        if stop_reason == "tool_use":
            tool_result_message = _handle_tool_use(output_message, request.no_cache)
            messages.append(tool_result_message)
            continue

        raise AgentLoopError(f"Unexpected stop reason from LLM backend: {stop_reason!r}")

    raise AgentLoopError(f"Agent loop exceeded {_MAX_ITERATIONS} iterations without finishing.")


# ---------------------------------------------------------------------------
# Format translation helpers
# ---------------------------------------------------------------------------


def _bedrock_toolspec_to_anthropic(spec: dict[str, Any]) -> dict[str, Any]:
    """Convert a Bedrock toolSpec dict to Anthropic tool format."""
    ts = spec["toolSpec"]
    return {
        "name": ts["name"],
        "description": ts["description"],
        "input_schema": ts["inputSchema"]["json"],
    }


def _bedrock_msg_to_anthropic(msg: dict[str, Any]) -> dict[str, Any]:
    """Convert a Bedrock-format message to Anthropic messages API format."""
    role = msg["role"]
    content = msg["content"]

    # Plain string content (initial user message)
    if isinstance(content, str):
        return {"role": role, "content": content}

    anthropic_content: list[dict[str, Any]] = []
    for block in content:
        block_type = block.get("type")

        if block_type == "text":
            anthropic_content.append({"type": "text", "text": block["text"]})

        elif block_type == "toolUse":
            anthropic_content.append(
                {
                    "type": "tool_use",
                    "id": block["toolUseId"],
                    "name": block["name"],
                    "input": block.get("input", {}),
                }
            )

        elif block_type == "toolResult":
            # Bedrock content: [{"json": {...}}]  →  Anthropic: string or list
            raw = block.get("content", [])
            if raw and isinstance(raw[0], dict) and "json" in raw[0]:
                result_content = json.dumps(raw[0]["json"])
            else:
                result_content = str(raw)
            anthropic_content.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block["toolUseId"],
                    "content": result_content,
                }
            )

    return {"role": role, "content": anthropic_content}


def _anthropic_response_to_bedrock(response: Any) -> dict[str, Any]:
    """Convert an Anthropic messages response to Bedrock output_message format."""
    bedrock_content: list[dict[str, Any]] = []

    for block in response.content:
        if block.type == "text":
            bedrock_content.append({"type": "text", "text": block.text})
        elif block.type == "tool_use":
            bedrock_content.append(
                {
                    "type": "toolUse",
                    "toolUseId": block.id,
                    "name": block.name,
                    "input": block.input,
                }
            )

    return {"role": "assistant", "content": bedrock_content}


# ---------------------------------------------------------------------------
# Shared loop helpers
# ---------------------------------------------------------------------------


def _build_initial_message(request: PlanRequest) -> str:
    """Build the initial user message from a PlanRequest."""
    assets_str = ", ".join(request.asset_profile)
    platforms_str = ", ".join(request.platforms)
    return (
        f"Please create a purple team adversary emulation plan with the following parameters:\n\n"
        f"Industry vertical: {request.vertical}\n"
        f"Key assets: {assets_str}\n"
        f"Target platforms: {platforms_str}\n"
        f"Number of TTPs to prioritize: {request.top_n}\n\n"
        "Work through both phases systematically using the available tools. "
        "Do not hallucinate any technique IDs, GUIDs, or ability IDs — only use "
        "values returned by the tools."
    )


def _handle_tool_use(assistant_message: dict[str, Any], no_cache: bool) -> dict[str, Any]:
    """Dispatch all tool calls in *assistant_message* and return a toolResult message."""
    content_blocks: list[dict[str, Any]] = assistant_message.get("content", [])
    tool_results: list[dict[str, Any]] = []

    for block in content_blocks:
        if block.get("type") != "toolUse":
            continue
        tool_use_id: str = block["toolUseId"]
        tool_name: str = block["name"]
        tool_input: dict[str, Any] = block.get("input", {})

        logger.debug("Dispatching tool: %s(%s)", tool_name, json.dumps(tool_input)[:200])

        try:
            result = dispatch(tool_name, tool_input, no_cache=no_cache)
        except Exception as exc:
            logger.warning("Tool %s raised exception: %s", tool_name, exc)
            result = {"error": str(exc)}

        tool_results.append(
            {
                "type": "toolResult",
                "toolUseId": tool_use_id,
                "content": [{"json": result}],
            }
        )

    return {"role": "user", "content": tool_results}


def _extract_emulation_plan(message: dict[str, Any]) -> EmulationPlan:
    """Parse the EmulationPlan JSON from the final assistant message."""
    full_text = ""
    for block in message.get("content", []):
        if block.get("type") == "text":
            full_text += block.get("text", "")

    match = re.search(r"```json\s*(\{.*?\})\s*```", full_text, re.DOTALL)
    if match:
        raw_json = match.group(1)
    else:
        match = re.search(r"(\{[\s\S]*\})", full_text)
        if not match:
            raise AgentLoopError("Agent did not produce a valid EmulationPlan JSON block.")
        raw_json = match.group(1)

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise AgentLoopError(f"Failed to parse EmulationPlan JSON: {exc}") from exc

    try:
        return EmulationPlan.model_validate(data)
    except Exception as exc:
        raise AgentLoopError(f"EmulationPlan validation failed: {exc}") from exc


def _emit_progress(callback: Any, turn: int, message: dict[str, Any]) -> None:
    """Extract a human-readable summary of the agent's turn and pass to callback."""
    parts: list[str] = []
    for block in message.get("content", []):
        if block.get("type") == "text":
            text = block.get("text", "").strip()
            if text:
                parts.append(f"[text] {text[:200]}")
        elif block.get("type") == "toolUse":
            name = block.get("name", "")
            inp = json.dumps(block.get("input", {}))[:100]
            parts.append(f"[tool] {name}({inp})")
    callback(turn, "\n".join(parts))
