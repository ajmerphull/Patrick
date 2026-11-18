from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .catalog import definition_cache_path, definition_update_status
from .mysql_advisories import load_mysql_definitions, mysql_definition_cache_path
from .php_version_profile import (
    normalize_php_version_profile,
    php_branch_sort_key,
)
from .scanner import Rule, load_rules


_BUNDLED_CATALOG = Path(__file__).parent / "rules" / "php-runtime.json"


def _publication_date(value: Any) -> tuple[datetime | None, str | None, str]:
    if not isinstance(value, str) or not value.strip():
        return None, None, "missing"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None, value, "invalid"
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed, value, "available"


def _metadata_status(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "missing"
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return "invalid"
    return "available"


def _sort_definitions(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dated = [row for row in rows if row["_publication_order"] is not None]
    undated = [row for row in rows if row["_publication_order"] is None]
    dated.sort(key=lambda row: (row["id"], row["component"], row["catalog"]))
    dated.sort(key=lambda row: row["_publication_order"], reverse=True)
    undated.sort(key=lambda row: (row["id"], row["component"], row["catalog"]))
    for row in dated + undated:
        row.pop("_publication_order")
    return dated + undated


def available_php_versions(php_catalog: Path | None = None) -> list[str]:
    branches = {
        branch
        for rule in load_rules(php_catalog)
        for branch in rule.fixed_versions
    }
    return sorted(branches, key=php_branch_sort_key, reverse=True)


def default_php_version(php_catalog: Path | None = None) -> str:
    branches = available_php_versions(php_catalog)
    if php_catalog is None:
        profile = definition_update_status().get("php_version_profile")
        if profile == "all":
            return "all"
        if isinstance(profile, str):
            return profile
    return branches[0] if branches else "all"


def _rule_affects_php_version(rule: Rule, branch: str) -> bool:
    fixed_version = rule.fixed_versions.get(branch)
    if fixed_version is None:
        return False
    branch_start = (*php_branch_sort_key(branch), 0)
    return fixed_version > branch_start


def list_vulnerability_definitions(
    php_catalog: Path | None = None,
    php_version: str | None = None,
) -> dict[str, Any]:
    issues: list[str] = []
    if php_catalog is None:
        cached_path = definition_cache_path()
        if cached_path.is_file():
            active_php_catalog = cached_path
            php_catalog_name = "updated local PHP catalog"
            php_catalog_status = definition_update_status()
            php_catalog_state = str(php_catalog_status.get("status", "unknown"))
            php_checked_at = php_catalog_status.get("checked_at")
            stored_php_version = php_catalog_status.get("php_version_profile")
            php_catalog_issues = [
                item
                for item in php_catalog_status.get("issues", [])
                if isinstance(item, str)
            ]
            if (
                php_catalog_state in {"updated", "partial"}
                and _metadata_status(php_checked_at) != "available"
            ):
                php_catalog_state = "unknown"
                php_catalog_issues.append(
                    "The updated PHP catalog has no valid check timestamp."
                )
        else:
            active_php_catalog = _BUNDLED_CATALOG
            php_catalog_name = "bundled PHP catalog"
            php_catalog_state = "bundled"
            php_checked_at = None
            stored_php_version = None
            php_catalog_issues = []
    else:
        active_php_catalog = php_catalog
        php_catalog_name = f"custom PHP catalog ({php_catalog})"
        php_catalog_state = "custom"
        php_checked_at = None
        stored_php_version = None
        php_catalog_issues = []

    profile_value = (
        stored_php_version
        if php_version is None and isinstance(stored_php_version, str)
        else php_version
    )
    selected_php_version = normalize_php_version_profile(profile_value)
    try:
        rules = load_rules(active_php_catalog)
    except ValueError as exc:
        raise ValueError(f"Could not load PHP definition catalog: {exc}") from exc
    php_rules = [
        rule
        for rule in rules
        if selected_php_version is None
        or _rule_affects_php_version(rule, selected_php_version)
    ]
    rows: list[dict[str, Any]] = []
    for rule in php_rules:
        published_order, published_at, date_status = _publication_date(
            rule.published_at
        )
        component = rule.component
        title_status = "available" if rule.title.strip() else "missing"
        severity_status = "available" if rule.severity.strip() else "missing"
        references_status = "available" if rule.references else "missing"
        rows.append(
            {
                "id": rule.id,
                "published_at": published_at,
                "publication_date_status": date_status,
                "title": rule.title if title_status == "available" else None,
                "title_status": title_status,
                "severity": (
                    rule.severity if severity_status == "available" else None
                ),
                "severity_status": severity_status,
                "component": component,
                "package_name": rule.package_name,
                "catalog": php_catalog_name,
                "references": list(rule.references),
                "references_status": references_status,
                "_publication_order": published_order,
            }
        )
        for field_name, field_status in (
            ("title", title_status),
            ("severity", severity_status),
            ("references", references_status),
        ):
            if field_status != "available":
                issues.append(
                    f"{rule.id} in {php_catalog_name} has {field_status} {field_name} metadata."
                )
        if date_status != "available":
            issues.append(
                f"{rule.id} in {php_catalog_name} has a {date_status} publication date."
            )

    mysql_catalog_path = mysql_definition_cache_path()
    mysql_catalog = load_mysql_definitions(mysql_catalog_path)
    mysql_state = str(mysql_catalog.get("status", "unknown"))
    mysql_catalog_name = "updated local MySQL catalog"
    mysql_checked_at = mysql_catalog.get("checked_at")
    mysql_issues = [
        item
        for item in mysql_catalog.get("issues", [])
        if isinstance(item, str)
    ]
    if (
        mysql_state in {"updated", "partial"}
        and _metadata_status(mysql_checked_at) != "available"
    ):
        mysql_state = "unknown"
        mysql_issues.append(
            "The local MySQL catalog has no valid check timestamp."
        )
    if mysql_state == "updated" and not mysql_catalog.get("rules"):
        mysql_state = "unknown"
        mysql_issues.append(
            "The local MySQL catalog is marked updated but contains no definitions."
        )
    for rule in mysql_catalog.get("rules", []):
        if selected_php_version is not None:
            continue
        if not isinstance(rule, dict):
            continue
        published_order, published_at, date_status = _publication_date(
            rule.get("published_at")
        )
        component = "mysql-server"
        rule_id = rule.get("id")
        if not isinstance(rule_id, str):
            issues.append("A MySQL catalog entry has no valid CVE identifier.")
            continue
        title = rule.get("title")
        title_status = (
            "available"
            if isinstance(title, str) and title.strip()
            else "missing"
        )
        if title_status != "available":
            title = None
            issues.append(f"{rule_id} in {mysql_catalog_name} has no title.")
        severity = rule.get("severity")
        severity_status = (
            "available"
            if isinstance(severity, str) and severity.strip()
            else "missing"
        )
        if severity_status != "available":
            issues.append(f"{rule_id} in {mysql_catalog_name} has no severity.")
        references = rule.get("references")
        references_status = (
            "missing"
            if not isinstance(references, list)
            else "invalid"
            if any(not isinstance(item, str) for item in references)
            else "available"
        )
        if references_status != "available":
            issues.append(
                f"{rule_id} in {mysql_catalog_name} has {references_status} reference metadata."
            )
        rows.append(
            {
                "id": rule_id,
                "published_at": published_at,
                "publication_date_status": date_status,
                "title": title,
                "title_status": title_status,
                "severity": severity if severity_status == "available" else None,
                "severity_status": severity_status,
                "component": component,
                "package_name": "Oracle MySQL Server",
                "catalog": mysql_catalog_name,
                "references": (
                    [item for item in references if isinstance(item, str)]
                    if isinstance(references, list)
                    else []
                ),
                "references_status": references_status,
                "_publication_order": published_order,
            }
        )
        if date_status != "available":
            issues.append(
                f"{rule_id} in {mysql_catalog_name} has a {date_status} publication date."
            )

    issues.extend(php_catalog_issues)
    php_core_count = sum(rule.component == "php-core" for rule in php_rules)
    php_extension_count = sum(
        rule.component == "php-extension" for rule in php_rules
    )
    if selected_php_version is not None and php_core_count == 0:
        issues.append(
            f"No PHP-core definitions in the local catalog identify PHP "
            f"{selected_php_version} as affected; this is not evidence that the "
            "branch has no vulnerabilities."
        )
    if selected_php_version is None:
        issues.extend(mysql_issues)
    definitions = _sort_definitions(rows)
    incomplete_states = {"partial", "unknown", "unavailable"}
    status = (
        "partial"
        if issues
        or php_catalog_state in incomplete_states
        or (
            selected_php_version is None
            and mysql_state in incomplete_states
        )
        else "complete"
    )
    return {
        "schema_version": 1,
        "feature": "Vulnerability Definition List",
        "mode": "vulnerability-definition-list",
        "status": status,
        "definition_count": len(definitions),
        "php_version_profile": selected_php_version or "all",
        "php_profile_counts": {
            "php_core": php_core_count,
            "php_extensions": php_extension_count,
        },
        "definitions": definitions,
        "catalogs": {
            "php": {
                "source": php_catalog_name,
                "status": php_catalog_state,
                "path": str(active_php_catalog),
                "checked_at": php_checked_at,
                "php_version_profile": selected_php_version or "all",
                "included_in_profile": True,
                "issues": php_catalog_issues,
            },
            "mysql": {
                "source": mysql_catalog_name,
                "status": mysql_state,
                "path": str(mysql_catalog_path),
                "checked_at": mysql_checked_at,
                "included_in_profile": selected_php_version is None,
                "issues": mysql_issues,
            },
        },
        "issues": issues,
        "limitations": [
            "This list contains definitions present in the selected local catalogs; it is not a complete feed of all known vulnerabilities.",
            "PHP source-signature rules and OSV dependency responses are not CVE runtime definitions and are not included.",
            (
                "The PHP version profile includes definitions with affected-version data for that PHP branch; it does not prove complete advisory coverage."
                if selected_php_version is not None
                else "MySQL definitions are included when the local MySQL catalog is available; missing or partial catalog coverage is reported."
            ),
            (
                "PHP extension advisories are lower-priority, best-effort coverage; not all PHP extensions or their vulnerabilities are included."
                if selected_php_version is not None
                else "PHP extension advisories are lower-priority, best-effort coverage; not all PHP extensions or their vulnerabilities are included."
            ),
        ],
    }
