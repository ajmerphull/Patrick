from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .definitions import _fetch_nvd_cves_for_cpe


_CPE = "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,3}$")
_MAX_CATALOG_BYTES = 16 * 1024 * 1024


def mysql_definition_cache_path() -> Path:
    cache_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return cache_root / "patrick" / "mysql-advisories.json"


def _parse_cpe(criteria: Any) -> tuple[str, str, str] | None:
    if not isinstance(criteria, str):
        return None
    fields = criteria.split(":")
    if len(fields) != 13 or fields[:3] != ["cpe", "2.3", "a"]:
        return None
    return fields[3].lower(), fields[4].lower(), fields[5]


def _range_from_match(match: dict[str, Any]) -> dict[str, str] | None:
    parsed = _parse_cpe(match.get("criteria"))
    if parsed is None or parsed[:2] != ("oracle", "mysql"):
        return None
    version = parsed[2]
    bounds = {
        key: match.get(key)
        for key in (
            "versionStartIncluding",
            "versionStartExcluding",
            "versionEndIncluding",
            "versionEndExcluding",
        )
        if match.get(key) is not None
    }
    if version != "*":
        if not _VERSION_RE.fullmatch(version) or bounds:
            raise ValueError("NVD MySQL CPE has an unsupported exact version range.")
        return {"exact": version}
    if not bounds or any(
        not isinstance(value, str) or not _VERSION_RE.fullmatch(value)
        for value in bounds.values()
    ):
        raise ValueError("NVD MySQL CPE has an unsupported or unbounded version range.")
    if (
        "versionStartIncluding" in bounds and "versionStartExcluding" in bounds
    ) or (
        "versionEndIncluding" in bounds and "versionEndExcluding" in bounds
    ):
        raise ValueError("NVD MySQL CPE has conflicting version boundaries.")
    lower = bounds.get("versionStartIncluding", bounds.get("versionStartExcluding"))
    upper = bounds.get("versionEndIncluding", bounds.get("versionEndExcluding"))
    if lower is not None and upper is not None:
        ordering = _compare_versions(lower, upper)
        if ordering > 0 or (
            ordering == 0
            and (
                "versionStartExcluding" in bounds
                or "versionEndExcluding" in bounds
            )
        ):
            raise ValueError("NVD MySQL CPE has an empty version range.")
    return bounds


def _mysql_ranges(cve: dict[str, Any]) -> tuple[list[dict[str, str]], bool]:
    configurations = cve.get("configurations")
    if not isinstance(configurations, list):
        return [], True
    ranges: list[dict[str, str]] = []
    unsupported = False

    def visit(node: Any) -> None:
        nonlocal unsupported
        if not isinstance(node, dict):
            unsupported = True
            return
        operator = node.get("operator", "OR")
        cpe_matches = node.get("cpeMatch", [])
        children = node.get("nodes", [])
        if not isinstance(cpe_matches, list) or not isinstance(children, list):
            unsupported = True
            return
        matching = [
            item
            for item in cpe_matches
            if isinstance(item, dict)
            and _parse_cpe(item.get("criteria")) is not None
            and _parse_cpe(item.get("criteria"))[:2] == ("oracle", "mysql")
        ]
        other_matches = len(cpe_matches) - len(matching)
        if matching and (
            node.get("negate") is True
            or operator not in {"AND", "OR"}
            or (
                operator == "AND"
                and (other_matches or children or len(matching) > 1)
            )
        ):
            unsupported = True
        elif matching:
            for item in matching:
                if item.get("vulnerable") is not True:
                    continue
                try:
                    value = _range_from_match(item)
                except ValueError:
                    unsupported = True
                    continue
                if value is not None and value not in ranges:
                    ranges.append(value)
        for child in children:
            visit(child)

    for configuration in configurations:
        if not isinstance(configuration, dict):
            unsupported = True
            continue
        nodes = configuration.get("nodes", [])
        if not isinstance(nodes, list):
            unsupported = True
            continue
        for node in nodes:
            visit(node)
    return ranges, unsupported


def _severity(cve: dict[str, Any]) -> str:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return "unknown"
    scores: list[tuple[float, str]] = []
    for rows in metrics.values():
        if not isinstance(rows, list):
            continue
        for row in rows:
            data = row.get("cvssData") if isinstance(row, dict) else None
            score = data.get("baseScore") if isinstance(data, dict) else None
            severity = data.get("baseSeverity") if isinstance(data, dict) else None
            if isinstance(score, (int, float)):
                scores.append((float(score), severity if isinstance(severity, str) else ""))
    if not scores:
        return "unknown"
    score, label = max(scores, key=lambda item: item[0])
    if label.lower() in {"critical", "high", "medium", "low"}:
        return label.lower()
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _rule(cve: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not _CVE_RE.fullmatch(cve_id):
        raise ValueError("NVD MySQL record has an invalid CVE identifier.")
    if cve.get("vulnStatus") == "Rejected":
        return None
    ranges, unsupported = _mysql_ranges(cve)
    if unsupported:
        raise ValueError(f"{cve_id} contains MySQL ranges that cannot be assessed safely.")
    if not ranges:
        return None
    descriptions = cve.get("descriptions")
    summary = next(
        (
            item.get("value")
            for item in descriptions
            if isinstance(item, dict)
            and item.get("lang") == "en"
            and isinstance(item.get("value"), str)
            and item["value"].strip()
        ),
        None,
    ) if isinstance(descriptions, list) else None
    published = cve.get("published")
    modified = cve.get("lastModified")
    if not isinstance(summary, str) or not isinstance(published, str) or not isinstance(modified, str):
        raise ValueError(f"{cve_id} is missing its description or timestamps.")
    references = cve.get("references")
    urls = [
        item["url"]
        for item in references
        if isinstance(item, dict)
        and isinstance(item.get("url"), str)
        and item["url"].startswith(("https://", "http://"))
    ] if isinstance(references, list) else []
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    return {
        "id": cve_id,
        "title": summary.split(". ", 1)[0][:180] or cve_id,
        "summary": summary.strip(),
        "severity": _severity(cve),
        "ranges": ranges,
        "published_at": published,
        "last_modified": modified,
        "references": list(dict.fromkeys([nvd_url, *urls])),
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=2, sort_keys=True)
    if len(content.encode("utf-8")) > _MAX_CATALOG_BYTES:
        raise OSError("MySQL advisory catalog exceeds the 16 MiB size limit.")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def refresh_mysql_definitions(*, cache_file: Path | None = None) -> dict[str, Any]:
    cache_file = cache_file or mysql_definition_cache_path()
    try:
        records, source = _fetch_nvd_cves_for_cpe(_CPE)
    except ValueError as exc:
        return {
            "status": "unavailable",
            "catalog_path": str(cache_file),
            "rules": 0,
            "issues": [str(exc)],
        }
    rules: list[dict[str, Any]] = []
    issues: list[str] = []
    seen: set[str] = set()
    unmodelled = 0
    for cve in records:
        if not isinstance(cve, dict):
            issues.append("NVD returned a malformed MySQL CVE record.")
            continue
        try:
            rule = _rule(cve)
        except ValueError as exc:
            issues.append(str(exc))
            continue
        if rule is None:
            if cve.get("vulnStatus") != "Rejected":
                unmodelled += 1
            continue
        if rule["id"] in seen:
            issues.append(f"{rule['id']} appeared more than once in the NVD MySQL result.")
            continue
        seen.add(rule["id"])
        rules.append(rule)
    if not rules:
        issues.append("NVD returned no safely modelled MySQL vulnerability ranges.")
    if unmodelled:
        issues.append(
            f"{unmodelled} NVD MySQL record(s) had no supported advisory range."
        )
    status = "updated" if not issues else "partial"
    catalog = {
        "schema_version": 1,
        "product": "Oracle MySQL Server",
        "checked_at": _now(),
        "source": source,
        "status": status,
        "rules": rules,
        "out_of_scope_records": unmodelled,
        "issues": issues,
    }
    try:
        _save(cache_file, catalog)
    except OSError as exc:
        issues.append(f"Could not save MySQL advisory definitions: {exc}")
        status = "partial"
    return {
        "status": status,
        "catalog_path": str(cache_file),
        "nvd_records": source["records"],
        "rules": len(rules),
        "out_of_scope_records": unmodelled,
        "issues": issues,
        "source": source,
    }


def load_mysql_definitions(cache_file: Path | None = None) -> dict[str, Any]:
    path = cache_file or mysql_definition_cache_path()
    try:
        if path.stat().st_size > _MAX_CATALOG_BYTES:
            raise ValueError("MySQL advisory catalog exceeds the size limit.")
        catalog: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {
            "status": "unavailable",
            "issues": ["No local MySQL advisory definitions are available."],
            "rules": [],
            "checked_at": None,
        }
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return {
            "status": "unknown",
            "issues": [f"Could not read local MySQL advisory definitions: {exc}"],
            "rules": [],
            "checked_at": None,
        }
    rule_ids: set[str] = set()
    valid_rules = isinstance(catalog, dict) and isinstance(
        catalog.get("rules"), list
    )
    if valid_rules:
        for rule in catalog["rules"]:
            if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                if rule["id"] in rule_ids:
                    valid_rules = False
                    break
                rule_ids.add(rule["id"])
            else:
                valid_rules = False
                break
    if (
        not isinstance(catalog, dict)
        or catalog.get("schema_version") != 1
        or catalog.get("product") != "Oracle MySQL Server"
        or catalog.get("status") not in {"updated", "partial"}
        or not isinstance(catalog.get("rules"), list)
        or not valid_rules
        or not isinstance(catalog.get("issues"), list)
        or any(not isinstance(issue, str) for issue in catalog["issues"])
        or not isinstance(catalog.get("checked_at"), str)
        or not isinstance(catalog.get("source"), dict)
        or any(
            not isinstance(rule, dict)
            or not isinstance(rule.get("id"), str)
            or not _CVE_RE.fullmatch(rule["id"])
            or not isinstance(rule.get("summary"), str)
            or not isinstance(rule.get("severity"), str)
            or not isinstance(rule.get("ranges"), list)
            or not rule["ranges"]
            or any(
                not isinstance(version_range, dict)
                or not version_range
                or (
                    "exact" in version_range and len(version_range) != 1
                )
                or any(
                    key not in {
                        "exact",
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    }
                    or not isinstance(value, str)
                    or not _VERSION_RE.fullmatch(value)
                    for key, value in version_range.items()
                )
                for version_range in rule["ranges"]
            )
            for rule in catalog["rules"]
        )
    ):
        return {
            "status": "unknown",
            "issues": ["Local MySQL advisory catalog has an invalid schema."],
            "rules": [],
            "checked_at": None,
        }
    return catalog


def version_tuple(version: str) -> tuple[int, ...] | None:
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        return None
    return tuple(int(part) for part in version.split("."))


def _compare_versions(left: str, right: str) -> int:
    left_parts = version_tuple(left)
    right_parts = version_tuple(right)
    if left_parts is None or right_parts is None:
        raise ValueError("Cannot compare malformed MySQL versions.")
    length = max(len(left_parts), len(right_parts))
    left_parts = left_parts + (0,) * (length - len(left_parts))
    right_parts = right_parts + (0,) * (length - len(right_parts))
    return (left_parts > right_parts) - (left_parts < right_parts)


def _range_matches(version: str, version_range: dict[str, str]) -> bool:
    if "exact" in version_range:
        return _compare_versions(version, version_range["exact"]) == 0
    checks = (
        ("versionStartIncluding", lambda result: result >= 0),
        ("versionStartExcluding", lambda result: result > 0),
        ("versionEndIncluding", lambda result: result <= 0),
        ("versionEndExcluding", lambda result: result < 0),
    )
    return all(
        check(_compare_versions(version, version_range[key]))
        for key, check in checks
        if key in version_range
    )


def assess_mysql_version(version: str, catalog: dict[str, Any]) -> dict[str, Any]:
    parsed = version_tuple(version)
    if parsed is None:
        return {
            "status": "unknown",
            "version": version,
            "findings": [],
            "issues": ["MySQL version is not a supported numeric release."],
        }
    if catalog["status"] == "unavailable" or not catalog.get("rules"):
        return {
            "status": "unknown",
            "version": version,
            "findings": [],
            "issues": list(catalog.get("issues", [])),
            "definitions_checked_at": catalog.get("checked_at"),
        }
    findings = []
    for rule in catalog["rules"]:
        if any(_range_matches(version, item) for item in rule.get("ranges", [])):
            findings.append({**rule, "status": "potentially_affected"})
    status = (
        "potentially_affected"
        if findings
        else "unknown"
        if catalog["status"] == "partial"
        else "no_known_vulnerabilities"
    )
    return {
        "status": status,
        "version": version,
        "findings": findings,
        "issues": list(catalog.get("issues", [])),
        "definitions_checked_at": catalog.get("checked_at"),
    }
