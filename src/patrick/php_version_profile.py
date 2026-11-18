from __future__ import annotations

import re


_PHP_BRANCH_RE = re.compile(r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")


def normalize_php_version_profile(value: object | None) -> str | None:
    if value is None or value == "all":
        return None
    if not isinstance(value, str) or not _PHP_BRANCH_RE.fullmatch(value):
        raise ValueError(
            "PHP version profile must be a major.minor branch such as 8.2, or 'all'."
        )
    return value


def php_branch_sort_key(branch: str) -> tuple[int, int]:
    major, minor = branch.split(".", 1)
    return int(major), int(minor)
