from __future__ import annotations

import json
import os
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


_SOURCE = "https://www.php.net/releases/index.php?json&version="
_SOURCE_ROOT = "https://www.php.net/"
_CACHE_SCHEMA_VERSION = 1
_MAX_RESPONSE_BYTES = 65_536
_BRANCH_RE = re.compile(r"^\d+\.\d+$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_REQUEST_TIMEOUT_SECONDS = 4


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cache_path() -> Path:
    cache_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return cache_root / "patrick" / "php-releases.json"


def _fetch_branch(branch: str) -> dict[str, Any]:
    url = f"{_SOURCE}{branch}"
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Patrick/0.1",
        },
    )
    try:
        with urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            if response.geturl().split("/", 3)[:3] != _SOURCE_ROOT.rstrip("/").split("/"):
                raise ValueError("PHP release endpoint redirected outside www.php.net.")
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except (OSError, URLError, TimeoutError) as exc:
        raise ValueError(f"Unable to fetch PHP {branch} release metadata: {exc}") from exc

    if len(raw) > _MAX_RESPONSE_BYTES:
        raise ValueError(f"PHP {branch} release metadata exceeds the size limit.")
    try:
        data: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"PHP {branch} release metadata is not valid UTF-8 JSON.") from exc

    if not isinstance(data, dict):
        raise ValueError(f"PHP {branch} release metadata has an invalid shape.")
    version = data.get("version")
    release_date = data.get("date")
    tags = data.get("tags")
    supported_versions = data.get("supported_versions")
    if (
        not isinstance(version, str)
        or not _VERSION_RE.fullmatch(version)
        or ".".join(version.split(".")[:2]) != branch
        or not isinstance(release_date, str)
        or not release_date
        or not isinstance(tags, list)
        or any(not isinstance(tag, str) for tag in tags)
        or not isinstance(supported_versions, list)
        or any(
            not isinstance(item, str) or not _BRANCH_RE.fullmatch(item)
            for item in supported_versions
        )
    ):
        raise ValueError(f"PHP {branch} release metadata failed validation.")

    return {
        "version": version,
        "date": release_date,
        "supported": branch in supported_versions,
        "security_release": "security" in tags,
        "source_url": url,
        "checked_at": _now(),
    }


def _load_cache(path: Path) -> tuple[dict[str, dict[str, Any]], str | None]:
    try:
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {}, f"Could not read PHP release cache; ignoring it: {exc}"

    if not isinstance(raw, dict) or raw.get("schema_version") != _CACHE_SCHEMA_VERSION:
        return {}, "PHP release cache has an unsupported or invalid schema; ignoring it."
    releases = raw.get("releases")
    if not isinstance(releases, dict):
        return {}, "PHP release cache has an invalid releases table; ignoring it."

    valid: dict[str, dict[str, Any]] = {}
    for branch, release in releases.items():
        if (
            isinstance(branch, str)
            and _BRANCH_RE.fullmatch(branch)
            and isinstance(release, dict)
            and isinstance(release.get("version"), str)
            and _VERSION_RE.fullmatch(release["version"])
            and ".".join(release["version"].split(".")[:2]) == branch
            and isinstance(release.get("date"), str)
            and isinstance(release.get("supported"), bool)
            and isinstance(release.get("security_release"), bool)
            and isinstance(release.get("source_url"), str)
            and isinstance(release.get("checked_at"), str)
        ):
            valid[branch] = release
    issue = (
        "PHP release cache contained invalid entries; ignoring those entries."
        if len(valid) != len(releases)
        else None
    )
    return valid, issue


def _save_cache(path: Path, releases: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(
        {"schema_version": _CACHE_SCHEMA_VERSION, "releases": releases},
        indent=2,
        sort_keys=True,
    )
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(content)
            temp_file.write("\n")
        os.replace(temp_path, path)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def refresh_php_releases(
    branches: set[str], *, cache_file: Path | None = None
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Fetch official PHP release facts, falling back to the local cache."""
    cache_file = cache_file or _cache_path()
    cached, cache_issue = _load_cache(cache_file)
    releases: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    branches = {branch for branch in branches if _BRANCH_RE.fullmatch(branch)}

    with ThreadPoolExecutor(max_workers=max(1, min(4, len(branches)))) as pool:
        futures = {branch: pool.submit(_fetch_branch, branch) for branch in branches}
        for branch, future in futures.items():
            try:
                releases[branch] = future.result(timeout=_REQUEST_TIMEOUT_SECONDS + 1)
            except (TimeoutError, ValueError) as exc:
                errors.append(str(exc))
                if branch in cached:
                    releases[branch] = cached[branch]

    if errors and cache_issue:
        errors.append(cache_issue)
    if any(branch not in releases for branch in branches):
        errors.append("No cached PHP release metadata is available for every requested branch.")

    if releases:
        merged_cache = {**cached, **releases}
        try:
            _save_cache(cache_file, merged_cache)
        except OSError as exc:
            errors.append(f"Could not save the PHP release cache: {exc}")

    if not errors:
        status = "updated"
    elif releases and all(branch in releases for branch in branches):
        status = "cached"
    elif releases:
        status = "partial"
    else:
        status = "unavailable"

    return releases, {
        "status": status,
        "source": "PHP.net official release metadata",
        "checked_at": _now(),
        "issues": errors,
    }
