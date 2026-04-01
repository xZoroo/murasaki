"""Atomic Red Team data loader.

Fetches per-technique YAML files from the redcanaryco/atomic-red-team GitHub repo
and caches them locally. Returns structured AtomicTest instances.
"""

import json
import logging
from pathlib import Path

import httpx
import yaml
from platformdirs import user_cache_dir

from murasaki.models import AtomicTest

logger = logging.getLogger(__name__)

_CACHE_DIR = Path(user_cache_dir("murasaki")) / "art"
_ART_RAW_URL = (
    "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics"
    "/{technique_id}/{technique_id}.yaml"
)


def get_atomic_tests(technique_id: str, no_cache: bool = False) -> list[AtomicTest]:
    """Return Atomic Red Team tests for *technique_id*.

    Results are cached to disk. Pass *no_cache=True* to bypass the disk cache.
    """
    tid = technique_id.upper()
    cache_path = _CACHE_DIR / f"{tid}.json"

    if not no_cache and cache_path.exists():
        try:
            return [AtomicTest(**t) for t in json.loads(cache_path.read_text())]
        except Exception:
            logger.debug("Cache read failed for %s, re-fetching", tid)

    tests = _fetch_atomic_tests(tid)
    _write_cache(cache_path, tests)
    return tests


def _fetch_atomic_tests(technique_id: str) -> list[AtomicTest]:
    """Download and parse the YAML file for *technique_id* from GitHub."""
    url = _ART_RAW_URL.format(technique_id=technique_id)
    try:
        with httpx.Client(follow_redirects=True, timeout=30) as client:
            resp = client.get(url)
            if resp.status_code == 404:
                logger.debug("No Atomic Red Team tests found for %s", technique_id)
                return []
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("Failed to fetch ART tests for %s: %s", technique_id, exc)
        return []

    try:
        data = yaml.safe_load(resp.text)
    except yaml.YAMLError as exc:
        logger.warning("Failed to parse ART YAML for %s: %s", technique_id, exc)
        return []

    if not isinstance(data, dict):
        return []

    raw_tests: list[dict] = data.get("atomic_tests", [])
    results: list[AtomicTest] = []

    for test in raw_tests:
        guid = test.get("auto_generated_guid", "")
        name = test.get("name", "")
        platforms = test.get("supported_platforms", [])
        executor = test.get("executor", {})
        executor_type = executor.get("name", "") if isinstance(executor, dict) else ""
        description = test.get("description", "")

        if guid and name:
            results.append(
                AtomicTest(
                    guid=guid,
                    name=name,
                    platforms=platforms,
                    executor_type=executor_type,
                    description=description[:300],
                )
            )

    return results


def _write_cache(path: Path, tests: list[AtomicTest]) -> None:
    """Persist a list of AtomicTest instances to the cache directory."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([t.model_dump() for t in tests]))  # nosec B102 — fixed cache dir
    except OSError as exc:
        logger.debug("Failed to write ART cache for %s: %s", path.stem, exc)
