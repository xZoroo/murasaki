"""Caldera stockpile ability loader.

Builds and maintains a local index mapping ATT&CK technique IDs to Caldera
stockpile ability IDs by crawling the mitre/stockpile GitHub repo.

The index is stored at ~/.cache/murasaki/caldera_index.json and rebuilt
automatically when it is older than 24 hours.
"""

import json
import logging
import time
from pathlib import Path

import httpx
import yaml
from platformdirs import user_cache_dir

from murasaki.models import CalderaAbility

logger = logging.getLogger(__name__)

_CACHE_DIR = Path(user_cache_dir("murasaki"))
_INDEX_PATH = _CACHE_DIR / "caldera_index.json"
_INDEX_TTL_SECONDS = 86_400  # 24 hours

_STOCKPILE_API = "https://api.github.com/repos/mitre/stockpile/contents/data/abilities/{tactic}"
_STOCKPILE_RAW = (
    "https://raw.githubusercontent.com/mitre/stockpile/master/data/abilities/{tactic}/{file}"
)

_TACTICS = [
    "collection",
    "command-and-control",
    "credential-access",
    "defense-evasion",
    "discovery",
    "execution",
    "exfiltration",
    "impact",
    "initial-access",
    "lateral-movement",
    "persistence",
    "privilege-escalation",
    "reconnaissance",
    "resource-development",
]


def get_caldera_abilities(technique_id: str, no_cache: bool = False) -> list[CalderaAbility]:
    """Return Caldera stockpile abilities mapped to *technique_id*.

    Builds the full index on first call (or when the cache is stale).
    """
    index = _load_index(no_cache=no_cache)
    tid = technique_id.upper()
    abilities_raw = index.get(tid, [])
    return [CalderaAbility(**a) for a in abilities_raw]


# ---------------------------------------------------------------------------
# Index management
# ---------------------------------------------------------------------------


def _load_index(no_cache: bool = False) -> dict[str, list[dict]]:
    """Return the technique→ability index, rebuilding if stale."""
    if not no_cache and _INDEX_PATH.exists():
        age = time.time() - _INDEX_PATH.stat().st_mtime
        if age < _INDEX_TTL_SECONDS:
            try:
                return json.loads(_INDEX_PATH.read_text())
            except Exception:
                logger.debug("Failed to read Caldera index cache, rebuilding")

    logger.info("Building Caldera stockpile index (this may take a moment)…")
    index = _build_index()
    _write_index(index)
    return index


def _build_index() -> dict[str, list[dict]]:
    """Crawl the Caldera stockpile repo and build the technique→ability index."""
    index: dict[str, list[dict]] = {}

    with httpx.Client(follow_redirects=True, timeout=30) as client:
        for tactic in _TACTICS:
            files = _list_tactic_files(client, tactic)
            for filename in files:
                ability = _fetch_ability(client, tactic, filename)
                if ability is None:
                    continue
                tid = ability.get("technique_id", "")
                if not tid:
                    continue
                index.setdefault(tid.upper(), [])
                # Avoid duplicates
                existing_ids = {a["ability_id"] for a in index[tid.upper()]}
                if ability["ability_id"] not in existing_ids:
                    index[tid.upper()].append(ability)

    return index


def _list_tactic_files(client: httpx.Client, tactic: str) -> list[str]:
    """Return YAML filenames for a tactic subdirectory via the GitHub API."""
    url = _STOCKPILE_API.format(tactic=tactic)
    try:
        resp = client.get(url, headers={"Accept": "application/vnd.github+json"})
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return [entry["name"] for entry in resp.json() if entry["name"].endswith(".yml")]
    except Exception as exc:
        logger.debug("Failed to list stockpile files for tactic %s: %s", tactic, exc)
        return []


def _fetch_ability(client: httpx.Client, tactic: str, filename: str) -> dict | None:
    """Download and parse a single Caldera ability YAML file."""
    url = _STOCKPILE_RAW.format(tactic=tactic, file=filename)
    try:
        resp = client.get(url)
        if resp.status_code != 200:
            return None
        data = yaml.safe_load(resp.text)
    except Exception as exc:
        logger.debug("Failed to fetch ability %s/%s: %s", tactic, filename, exc)
        return None

    if not isinstance(data, dict):
        return None

    # Caldera YAML schema: top-level keys include id, name, tactic, technique, platforms
    technique = data.get("technique", {})
    if not isinstance(technique, dict):
        return None

    technique_id: str = technique.get("attack_id", "")
    if not technique_id:
        return None

    platforms_raw = data.get("platforms", {})
    platforms = list(platforms_raw.keys()) if isinstance(platforms_raw, dict) else []

    return {
        "ability_id": data.get("id", filename.replace(".yml", "")),
        "name": data.get("name", ""),
        "tactic": data.get("tactic", tactic),
        "platforms": platforms,
        "description": data.get("description", "")[:300],
        "technique_id": technique_id,
    }


def _write_index(index: dict[str, list[dict]]) -> None:
    """Persist the index to disk."""
    try:
        _INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
        _INDEX_PATH.write_text(json.dumps(index))
    except OSError as exc:
        logger.warning("Failed to write Caldera index cache: %s", exc)
