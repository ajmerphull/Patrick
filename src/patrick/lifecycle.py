from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


_SOURCE = "https://endoflife.date/api/php.json"
_CACHE_SCHEMA_VERSION = 1
_MAX_RESPONSE_BYTES = 524_288
_MAX_CACHE_BYTES = 1_048_576
_REQUEST_TIMEOUT_SECONDS = 4
_BRANCH_RE = re.compile(r"^\d+\.\d+$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cache_path() -> Path:
    cache_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return cache_root / "patrick" / "php-lifecycle.json"


def _parse_date(value: Any, *, allow_false: bool = False) -> str | None:
    if allow_false and (value is False or value is None):
        return None
    if not isinstance(value, str) or not _DATE_RE.fullmatch(value):
        raise ValueError(f"Invalid lifecycle date: {value!r}.")
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError(f"Invalid lifecycle date: {value!r}.") from exc
    return value


def _normalize_cycle(row: Any, checked_at: str) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise ValueError("PHP lifecycle record is not an object.")
    cycle = row.get("cycle")
    latest = row.get("latest")
    lts = row.get("lts")
    if (
        not isinstance(cycle, str)
        or not _BRANCH_RE.fullmatch(cycle)
        or not isinstance(latest, str)
        or not _VERSION_RE.fullmatch(latest)
        or ".".join(latest.split(".")[:2]) != cycle
        or not isinstance(lts, bool)
    ):
        raise ValueError("PHP lifecycle record has an invalid cycle or version.")
    release_date = _parse_date(row.get("releaseDate"))
    latest_release_date = _parse_date(row.get("latestReleaseDate"))
    support_date = _parse_date(row.get("support"), allow_false=True)
    eol_date = _parse_date(row.get("eol"), allow_false=True)
    return {
        "cycle": cycle,
        "release_date": release_date,
        "support_date": support_date,
        "eol_date": eol_date,
        "latest_version": latest,
        "latest_release_date": latest_release_date,
        "lts": lts,
        "source_url": _SOURCE,
        "checked_at": checked_at,
    }


def _parse_response(raw: bytes) -> dict[str, dict[str, Any]]:
    try:
        payload: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("PHP lifecycle response is not valid UTF-8 JSON.") from exc
    if not isinstance(payload, list) or not payload:
        raise ValueError("PHP lifecycle response must be a non-empty array.")
    checked_at = _now()
    cycles: dict[str, dict[str, Any]] = {}
    for row in payload:
        normalized = _normalize_cycle(row, checked_at)
        cycle = normalized["cycle"]
        if cycle in cycles:
            raise ValueError(f"PHP lifecycle response repeats cycle {cycle}.")
        cycles[cycle] = normalized
    return cycles


def _fetch_cycles() -> dict[str, dict[str, Any]]:
    request = Request(
        _SOURCE,
        headers={
            "Accept": "application/json",
            "User-Agent": "Patrick/0.1",
        },
    )
    try:
        with urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            parsed_url = urlsplit(response.geturl())
            if (
                parsed_url.scheme != "https"
                or parsed_url.hostname != "endoflife.date"
            ):
                raise ValueError(
                    "PHP lifecycle endpoint redirected outside endoflife.date."
                )
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except (OSError, URLError, TimeoutError) as exc:
        raise ValueError(f"Unable to fetch PHP lifecycle metadata: {exc}") from exc
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise ValueError("PHP lifecycle response exceeds the size limit.")
    return _parse_response(raw)


def _load_cache(path: Path) -> tuple[dict[str, dict[str, Any]], str | None]:
    try:
        if path.stat().st_size > _MAX_CACHE_BYTES:
            return {}, "PHP lifecycle cache exceeds the size limit; ignoring it."
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {}, f"Could not read PHP lifecycle cache; ignoring it: {exc}"
    if not isinstance(raw, dict) or raw.get("schema_version") != _CACHE_SCHEMA_VERSION:
        return {}, "PHP lifecycle cache has an unsupported or invalid schema; ignoring it."
    entries = raw.get("cycles")
    if not isinstance(entries, dict):
        return {}, "PHP lifecycle cache has an invalid cycles table; ignoring it."

    cycles: dict[str, dict[str, Any]] = {}
    for cycle, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        normalized_input = {
            "cycle": cycle,
            "releaseDate": entry.get("release_date"),
            "support": entry.get("support_date", False),
            "eol": entry.get("eol_date", False),
            "latest": entry.get("latest_version"),
            "latestReleaseDate": entry.get("latest_release_date"),
            "lts": entry.get("lts"),
        }
        try:
            normalized = _normalize_cycle(
                normalized_input,
                entry.get("checked_at")
                if isinstance(entry.get("checked_at"), str)
                else "",
            )
        except ValueError:
            continue
        if (
            entry.get("source_url") == _SOURCE
            and isinstance(entry.get("checked_at"), str)
            and entry.get("checked_at")
        ):
            cycles[cycle] = normalized
    issue = (
        "PHP lifecycle cache contained invalid entries; ignoring those entries."
        if len(cycles) != len(entries)
        else None
    )
    return cycles, issue


def _save_cache(path: Path, cycles: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(
        {"schema_version": _CACHE_SCHEMA_VERSION, "cycles": cycles},
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


def refresh_php_lifecycle(
    branches: set[str],
    *,
    offline: bool = False,
    cache_file: Path | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Fetch or read PHP branch lifecycle facts, using cache when needed."""
    cache_file = cache_file or _cache_path()
    cached, cache_issue = _load_cache(cache_file)
    requested = {branch for branch in branches if _BRANCH_RE.fullmatch(branch)}
    if not requested:
        return {}, {
            "status": "not_required",
            "source": "endoflife.date PHP lifecycle data",
            "issues": [],
        }

    errors: list[str] = []
    cycles: dict[str, dict[str, Any]]
    if offline:
        cycles = cached
        if not cycles:
            errors.append(
                "Offline PHP lifecycle check has no cached lifecycle metadata."
            )
    else:
        try:
            cycles = _fetch_cycles()
            try:
                _save_cache(cache_file, cycles)
            except OSError as exc:
                errors.append(f"Could not save the PHP lifecycle cache: {exc}")
        except ValueError as exc:
            errors.append(str(exc))
            cycles = cached

    if cache_issue:
        errors.append(cache_issue)
    selected = {branch: cycles[branch] for branch in requested if branch in cycles}
    missing = sorted(requested - selected.keys())
    if missing:
        errors.append(
            "No PHP lifecycle metadata is available for branch(es): "
            + ", ".join(missing)
            + "."
        )

    if not errors:
        status = "updated"
    elif selected and not missing:
        status = "cached"
    elif selected:
        status = "partial"
    else:
        status = "unavailable"
    return selected, {
        "status": status,
        "source": "endoflife.date PHP lifecycle data",
        "source_url": _SOURCE,
        "checked_at": _now(),
        "issues": errors,
    }
