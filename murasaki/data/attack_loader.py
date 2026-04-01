"""MITRE ATT&CK data loader using mitreattack-python.

Downloads and caches the enterprise ATT&CK STIX bundle locally, then exposes
thin query wrappers used by the agent tools.
"""

import logging
from pathlib import Path
from typing import Any

import httpx
from platformdirs import user_cache_dir

logger = logging.getLogger(__name__)

_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
_CACHE_DIR = Path(user_cache_dir("murasaki"))
_STIX_PATH = _CACHE_DIR / "enterprise-attack.json"

# Module-level singleton — populated on first call to _get_attack_data()
_attack_data: Any = None


def _download_stix_bundle(dest: Path) -> None:
    """Download the ATT&CK STIX bundle to *dest* with a progress log."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Downloading ATT&CK STIX bundle (this may take a moment)…")
    with httpx.Client(follow_redirects=True, timeout=120) as client:
        resp = client.get(_STIX_URL)
        resp.raise_for_status()
        dest.write_bytes(resp.content)
    logger.info("ATT&CK STIX bundle saved to %s", dest)


def _get_attack_data(stix_path: Path | None = None) -> Any:
    """Return the MitreAttackData singleton, downloading the bundle if needed."""
    global _attack_data  # noqa: PLW0603
    if _attack_data is not None:
        return _attack_data

    # Import here so the module loads even without the package installed during tests
    from mitreattack.stix20 import MitreAttackData  # type: ignore[import-untyped]

    bundle_path = stix_path or _STIX_PATH
    if not bundle_path.exists():
        _download_stix_bundle(bundle_path)

    _attack_data = MitreAttackData(str(bundle_path))
    return _attack_data


# ---------------------------------------------------------------------------
# Public query helpers
# ---------------------------------------------------------------------------


def search_groups_by_keyword(keywords: list[str]) -> list[dict[str, Any]]:
    """Return ATT&CK groups whose name, aliases, or description match any keyword."""
    data = _get_attack_data()
    groups = data.get_groups(remove_revoked_deprecated=True)
    results: list[dict[str, Any]] = []
    lower_kw = [k.lower() for k in keywords]

    for group in groups:
        name: str = group.get("name", "")
        aliases: list[str] = group.get("aliases", [])
        description: str = group.get("description", "")

        haystack = " ".join([name, *aliases, description]).lower()
        if any(kw in haystack for kw in lower_kw):
            attack_id = _extract_attack_id(group)
            if attack_id:
                results.append(
                    {
                        "group_id": attack_id,
                        "name": name,
                        "aliases": aliases,
                        "description": description[:300],
                    }
                )

    return results


def get_group_by_attack_id(group_id: str) -> dict[str, Any] | None:
    """Look up a single group by its ATT&CK ID (e.g. G0016)."""
    data = _get_attack_data()
    groups = data.get_groups(remove_revoked_deprecated=True)
    for group in groups:
        if _extract_attack_id(group) == group_id.upper():
            return {
                "group_id": group_id.upper(),
                "name": group.get("name", ""),
                "aliases": group.get("aliases", []),
                "description": group.get("description", ""),
            }
    return None


def get_techniques_for_group(group_id: str) -> list[dict[str, Any]]:
    """Return all techniques attributed to a group."""
    data = _get_attack_data()
    groups = data.get_groups(remove_revoked_deprecated=True)

    target_group = None
    for group in groups:
        if _extract_attack_id(group) == group_id.upper():
            target_group = group
            break

    if target_group is None:
        return []

    try:
        techniques = data.get_techniques_used_by_group(target_group["id"])
    except Exception:
        return []

    results: list[dict[str, Any]] = []
    for entry in techniques:
        technique = entry.get("object", {})
        t_id = _extract_attack_id(technique)
        if not t_id:
            continue
        tactics = [
            phase.get("phase_name", "")
            for phase in technique.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        platforms = technique.get("x_mitre_platforms", [])
        results.append(
            {
                "technique_id": t_id,
                "technique_name": technique.get("name", ""),
                "tactics": tactics,
                "platforms": platforms,
            }
        )

    return results


def get_technique_detail(technique_id: str) -> dict[str, Any] | None:
    """Return full detail for a technique including data sources and mitigations."""
    data = _get_attack_data()
    techniques = data.get_techniques(remove_revoked_deprecated=True)

    for technique in techniques:
        if _extract_attack_id(technique) == technique_id.upper():
            tactics = [
                phase.get("phase_name", "")
                for phase in technique.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]
            return {
                "technique_id": technique_id.upper(),
                "name": technique.get("name", ""),
                "description": technique.get("description", "")[:600],
                "tactics": tactics,
                "platforms": technique.get("x_mitre_platforms", []),
                "data_sources": technique.get("x_mitre_data_sources", []),
                "detection": technique.get("x_mitre_detection", "")[:400],
            }

    return None


def get_all_group_ids() -> list[str]:
    """Return all ATT&CK group IDs (for validation/testing)."""
    data = _get_attack_data()
    groups = data.get_groups(remove_revoked_deprecated=True)
    return [_extract_attack_id(g) for g in groups if _extract_attack_id(g)]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_attack_id(obj: dict[str, Any]) -> str:
    """Extract the ATT&CK external ID (e.g. G0016, T1059) from a STIX object."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def reset_singleton() -> None:
    """Reset the module-level singleton (used in tests)."""
    global _attack_data  # noqa: PLW0603
    _attack_data = None


def preload_stix_bundle(path: Path) -> None:
    """Force-load from a specific STIX bundle path (used in tests / CLI --stix-bundle)."""
    global _attack_data  # noqa: PLW0603
    _attack_data = None  # reset first
    _get_attack_data(stix_path=path)
