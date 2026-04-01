"""Tool registry for the murasaki Bedrock agent.

Defines the five tools surfaced to the LLM via toolConfig, and maps each
tool name to its Python handler function.
"""

from typing import Any

from murasaki.data import atomic_loader, attack_loader, caldera_loader

# ---------------------------------------------------------------------------
# Tool JSON schemas (Bedrock toolSpec format)
# ---------------------------------------------------------------------------

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "toolSpec": {
            "name": "get_groups_for_vertical",
            "description": (
                "Find ATT&CK threat actor groups that commonly target a given industry "
                "vertical and asset profile. Returns group IDs, names, aliases, and "
                "brief descriptions. Use this as the first step in TTP prioritization."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "vertical": {
                            "type": "string",
                            "description": "Industry vertical, e.g. 'financial services', 'healthcare'",  # noqa: E501
                        },
                        "asset_keywords": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Keywords describing the org's key assets, e.g. ['Active Directory', 'SWIFT']",  # noqa: E501
                        },
                    },
                    "required": ["vertical", "asset_keywords"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "get_techniques_for_group",
            "description": (
                "Return all ATT&CK techniques attributed to a specific threat actor group. "
                "Provide the ATT&CK group ID (e.g. G0016). Returns technique IDs, names, "
                "tactics, and target platforms."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "group_id": {
                            "type": "string",
                            "description": "ATT&CK group ID, e.g. 'G0016' or 'G0064'",
                        }
                    },
                    "required": ["group_id"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "get_technique_detail",
            "description": (
                "Get full details for a specific ATT&CK technique: description, tactics, "
                "target platforms, data sources for detection, and detection guidance. "
                "Use this to gather context before writing detection hypotheses."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "ATT&CK technique ID, e.g. 'T1059.001' or 'T1078'",
                        }
                    },
                    "required": ["technique_id"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "get_atomic_tests",
            "description": (
                "Fetch Atomic Red Team test entries for a specific ATT&CK technique. "
                "Returns test GUIDs, names, supported platforms, and executor types. "
                "These GUIDs are compatible with Invoke-AtomicRedTeam and Caldera."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "ATT&CK technique ID, e.g. 'T1059.001'",
                        }
                    },
                    "required": ["technique_id"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "get_caldera_abilities",
            "description": (
                "Look up Caldera stockpile ability IDs that map to a specific ATT&CK technique. "
                "Returns ability UUIDs, names, tactics, and supported platforms. "
                "These ability IDs can be used directly in Caldera adversary profiles."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "ATT&CK technique ID, e.g. 'T1059.001'",
                        }
                    },
                    "required": ["technique_id"],
                }
            },
        }
    },
]


# ---------------------------------------------------------------------------
# Handler dispatch
# ---------------------------------------------------------------------------


def dispatch(tool_name: str, tool_input: dict[str, Any], no_cache: bool = False) -> Any:
    """Route a tool call from the agent to the appropriate handler.

    Returns a JSON-serialisable value that will be sent back as a toolResult.
    """
    handlers = {
        "get_groups_for_vertical": _handle_get_groups_for_vertical,
        "get_techniques_for_group": _handle_get_techniques_for_group,
        "get_technique_detail": _handle_get_technique_detail,
        "get_atomic_tests": lambda inp: _handle_get_atomic_tests(inp, no_cache),
        "get_caldera_abilities": lambda inp: _handle_get_caldera_abilities(inp, no_cache),
    }
    handler = handlers.get(tool_name)
    if handler is None:
        return {"error": f"Unknown tool: {tool_name}"}
    return handler(tool_input)


def _handle_get_groups_for_vertical(inp: dict[str, Any]) -> Any:
    vertical: str = inp.get("vertical", "")
    asset_keywords: list[str] = inp.get("asset_keywords", [])
    keywords = [vertical] + asset_keywords
    return attack_loader.search_groups_by_keyword(keywords)


def _handle_get_techniques_for_group(inp: dict[str, Any]) -> Any:
    group_id: str = inp.get("group_id", "")
    return attack_loader.get_techniques_for_group(group_id)


def _handle_get_technique_detail(inp: dict[str, Any]) -> Any:
    technique_id: str = inp.get("technique_id", "")
    result = attack_loader.get_technique_detail(technique_id)
    if result is None:
        return {"error": f"Technique {technique_id} not found"}
    return result


def _handle_get_atomic_tests(inp: dict[str, Any], no_cache: bool) -> Any:
    technique_id: str = inp.get("technique_id", "")
    tests = atomic_loader.get_atomic_tests(technique_id, no_cache=no_cache)
    return [t.model_dump() for t in tests]


def _handle_get_caldera_abilities(inp: dict[str, Any], no_cache: bool) -> Any:
    technique_id: str = inp.get("technique_id", "")
    abilities = caldera_loader.get_caldera_abilities(technique_id, no_cache=no_cache)
    return [a.model_dump() for a in abilities]
