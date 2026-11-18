from __future__ import annotations

import json
import os
from pathlib import Path

from .php_version_profile import normalize_php_version_profile


def definition_cache_path() -> Path:
    configured_root = os.environ.get("XDG_CACHE_HOME")
    cache_root = Path(configured_root) if configured_root else Path.home() / ".cache"
    return cache_root / "patrick" / "php-runtime-updated.json"


def definition_update_status() -> dict[str, object]:
    path = definition_cache_path()
    if not path.exists():
        return {"status": "bundled", "issues": []}
    try:
        catalog = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {
            "status": "unknown",
            "issues": [f"Could not read definition update metadata: {exc}"],
        }

    metadata = catalog.get("update_metadata") if isinstance(catalog, dict) else None
    if not isinstance(metadata, dict):
        return {
            "status": "unknown",
            "issues": [
                "The local definition cache has no update status; refresh definitions before relying on it."
            ],
        }
    status = metadata.get("status")
    issues = metadata.get("issues")
    php_core_records = metadata.get("php_core_records")
    php_extension_records = metadata.get("php_extension_records")
    out_of_scope_records = metadata.get("out_of_scope_records")
    php_version_profile = metadata.get("php_version_profile")
    try:
        if php_version_profile is not None:
            normalize_php_version_profile(php_version_profile)
    except ValueError:
        return {
            "status": "unknown",
            "issues": ["The local definition update metadata has an invalid PHP version profile."],
        }
    if (
        status not in {"updated", "partial", "unavailable"}
        or not isinstance(issues, list)
        or any(not isinstance(issue, str) for issue in issues)
        or (status == "updated" and issues)
        or (
            php_core_records is not None
            and (not isinstance(php_core_records, int) or php_core_records < 0)
        )
        or (
            php_extension_records is not None
            and (
                not isinstance(php_extension_records, int)
                or php_extension_records < 0
            )
        )
        or (
            out_of_scope_records is not None
            and (
                not isinstance(out_of_scope_records, int)
                or out_of_scope_records < 0
            )
        )
    ):
        return {
            "status": "unknown",
            "issues": ["The local definition update metadata is invalid."],
        }
    return {
        "status": status,
        "checked_at": metadata.get("checked_at"),
        "issues": issues,
        "php_core_records": php_core_records,
        "php_extension_records": php_extension_records,
        "out_of_scope_records": out_of_scope_records,
        "php_version_profile": php_version_profile,
    }
