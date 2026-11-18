from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .mysql_advisories import assess_mysql_version, load_mysql_definitions
from .mysql_runtime import inspect_mysql_server


_OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch"
_MAX_LOCK_BYTES = 10 * 1024 * 1024
_MAX_PACKAGES = 1000
_BATCH_SIZE = 100
_MAX_OSV_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_OSV_TOTAL_RESPONSE_BYTES = 16 * 1024 * 1024
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}/[A-Za-z0-9_.-]{1,128}$")
_VERSION_RE = re.compile(r"^v?\d{1,12}\.\d{1,12}\.\d{1,12}(?:[-+][0-9A-Za-z.-]{1,128})?$")
_ADVISORY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, new_url):
        return None


def _read_composer_lock(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    issues: list[str] = []
    try:
        if path.is_symlink() or path.stat().st_size > _MAX_LOCK_BYTES:
            return [], ["composer.lock is a symlink or exceeds the 10 MiB size limit."]
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], ["No composer.lock was found; dependency versions cannot be verified."]
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [], [f"Could not read composer.lock: {exc}"]
    if not isinstance(raw, dict):
        return [], ["composer.lock root must be a JSON object."]
    packages: list[dict[str, str]] = []
    for section in ("packages", "packages-dev"):
        if section == "packages" and section not in raw:
            return [], ["composer.lock is missing its packages array."]
        rows = raw.get(section, [])
        if not isinstance(rows, list):
            issues.append(f"composer.lock {section} must be an array.")
            continue
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                issues.append(f"composer.lock {section}[{index}] is not an object.")
                continue
            name, version = row.get("name"), row.get("version")
            if not isinstance(name, str) or not _PACKAGE_RE.fullmatch(name):
                issues.append(
                    f"composer.lock {section}[{index}] has an invalid package name."
                )
                continue
            if not isinstance(version, str) or not version.strip():
                issues.append(
                    f"composer.lock {section}[{index}] has no exact package version."
                )
                continue
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "section": section,
                }
            )
    if len(packages) > _MAX_PACKAGES:
        issues.append(
            f"composer.lock contains more than {_MAX_PACKAGES} packages; later entries are not assessed."
        )
        packages = packages[:_MAX_PACKAGES]
    return packages, issues


def _query_osv(
    batch: list[tuple[str, str]],
    *,
    response_budget: int = _MAX_OSV_RESPONSE_BYTES,
) -> tuple[list[list[dict[str, Any]]], int]:
    body = {
        "queries": [
            {
                "package": {"name": name.lower(), "ecosystem": "Packagist"},
                "version": version.lstrip("v"),
            }
            for name, version in batch
        ]
    }
    request = Request(
        _OSV_ENDPOINT,
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Patrick/0.1",
        },
        method="POST",
    )
    try:
        opener = build_opener(_NoRedirectHandler)
        with opener.open(request, timeout=10) as response:
            final_url = urlsplit(response.geturl())
            if final_url.scheme != "https" or final_url.hostname != "api.osv.dev":
                raise ValueError("OSV query redirected outside api.osv.dev.")
            allowed_bytes = min(_MAX_OSV_RESPONSE_BYTES, response_budget)
            raw = response.read(allowed_bytes + 1)
    except (OSError, URLError, TimeoutError) as exc:
        raise ValueError(f"Unable to query OSV for Composer dependencies: {exc}") from exc
    if len(raw) > allowed_bytes:
        raise ValueError("OSV response exceeds the remaining response size budget.")
    try:
        payload: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("OSV response is not valid UTF-8 JSON.") from exc
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or len(results) != len(batch):
        raise ValueError("OSV response does not align with the submitted package queries.")
    normalized: list[list[dict[str, Any]]] = []
    for index, result in enumerate(results):
        vulns = result.get("vulns", []) if isinstance(result, dict) else None
        if not isinstance(vulns, list) or any(
            not isinstance(vuln, dict) for vuln in vulns
        ):
            raise ValueError(f"OSV result {index} has an invalid vulnerabilities list.")
        normalized.append(vulns)
    return normalized, len(raw)


def _project_vulnerability(vulnerability: dict[str, Any]) -> dict[str, Any]:
    vulnerability_id = vulnerability.get("id")
    if (
        not isinstance(vulnerability_id, str)
        or not _ADVISORY_ID_RE.fullmatch(vulnerability_id)
    ):
        raise ValueError("OSV returned a vulnerability with an invalid identifier.")
    references = vulnerability.get("references", [])
    if not isinstance(references, list):
        references = []
    urls = [
        item["url"]
        for item in references
        if isinstance(item, dict)
        and isinstance(item.get("url"), str)
        and item["url"].startswith(("https://", "http://"))
    ]
    summary = vulnerability.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        summary = vulnerability.get("details")
    if not isinstance(summary, str):
        summary = "OSV reports this locked package version as affected."
    return {
        "id": vulnerability_id,
        "summary": summary[:2000],
        "published": vulnerability.get("published"),
        "modified": vulnerability.get("modified"),
        "references": list(dict.fromkeys(urls[:20])),
        "source_url": f"https://osv.dev/vulnerability/{vulnerability_id}",
    }


def scan_dependencies(
    root: Path,
    *,
    mysql_binary: Path | None = None,
    offline: bool = False,
) -> dict[str, Any]:
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Target must be an existing directory: {root}")
    packages, issues = _read_composer_lock(root / "composer.lock")
    unique_queries = list(
        dict.fromkeys(
            (row["name"], row["version"])
            for row in packages
            if _PACKAGE_RE.fullmatch(row["name"])
            and _VERSION_RE.fullmatch(row["version"])
        )
    )
    query_results: dict[tuple[str, str], list[dict[str, Any]]] = {}
    query_errors: dict[tuple[str, str], str] = {}
    total_response_bytes = 0
    if offline and unique_queries:
        issues.append("OSV lookups were skipped by --offline; dependency results are unknown.")
    elif not offline:
        for offset in range(0, len(unique_queries), _BATCH_SIZE):
            batch = unique_queries[offset : offset + _BATCH_SIZE]
            remaining_budget = _MAX_OSV_TOTAL_RESPONSE_BYTES - total_response_bytes
            if remaining_budget <= 0:
                message = "OSV aggregate response size limit reached; remaining dependencies are unknown."
                issues.append(message)
                query_errors.update((query, message) for query in batch)
                continue
            try:
                results, response_bytes = _query_osv(
                    batch, response_budget=remaining_budget
                )
            except ValueError as exc:
                message = str(exc)
                issues.append(message)
                affected_queries = (
                    unique_queries[offset:]
                    if "remaining response size budget" in message
                    else batch
                )
                for query in affected_queries:
                    query_errors[query] = message
                if "remaining response size budget" in message:
                    break
                continue
            total_response_bytes += response_bytes
            for query, vulnerabilities in zip(batch, results):
                try:
                    query_results[query] = [
                        _project_vulnerability(item) for item in vulnerabilities
                    ]
                except ValueError as exc:
                    query_errors[query] = str(exc)
                    issues.append(str(exc))

    dependency_results: list[dict[str, Any]] = []
    for package in packages:
        query = (package["name"], package["version"])
        if not _VERSION_RE.fullmatch(package["version"]):
            status = "unknown"
            vulnerabilities: list[dict[str, Any]] = []
            reason = "The locked version is not a supported exact release version."
        elif query in query_errors:
            status = "unknown"
            vulnerabilities = []
            reason = query_errors[query]
        elif query in query_results:
            vulnerabilities = query_results[query]
            status = "potentially_affected" if vulnerabilities else "no_known_vulnerabilities"
            reason = (
                "OSV reports matching advisories for this exact locked version."
                if vulnerabilities
                else "OSV returned no matching advisories for this exact locked version."
            )
        else:
            status = "unknown"
            vulnerabilities = []
            reason = "No OSV result is available for this package and version."
        dependency_results.append(
            {
                **package,
                "status": status,
                "reason": reason,
                "vulnerabilities": vulnerabilities,
            }
        )

    mysql: dict[str, Any]
    if mysql_binary is None:
        mysql = {
            "status": "not_selected",
            "reason": "No MySQL server executable was selected.",
            "findings": [],
        }
    else:
        observation = inspect_mysql_server(mysql_binary)
        if observation["product"] != "Oracle MySQL":
            mysql = {
                **observation,
                "status": "unknown",
                "findings": [],
                "issues": [
                    f"{observation['product']} is not covered by the Oracle MySQL advisory catalog."
                ],
            }
        else:
            catalog = load_mysql_definitions()
            mysql = {
                **observation,
                **assess_mysql_version(observation["version"], catalog),
                "catalog_status": catalog["status"],
                "catalog_source": catalog.get("source"),
            }

    affected = any(
        row["status"] == "potentially_affected"
        for row in dependency_results
    ) or mysql["status"] == "potentially_affected"
    unknown = (
        any(row["status"] == "unknown" for row in dependency_results)
        or mysql["status"] in {"unknown", "unavailable", "not_selected"}
        or bool(issues)
    )
    if affected:
        status = "potentially_affected"
    elif unknown:
        status = "unknown"
    else:
        status = "no_known_issues"
    return {
        "schema_version": 1,
        "feature": "MySQL & Third-Party Dependency Scan",
        "mode": "mysql-third-party-dependency-scan",
        "target": str(root),
        "status": status,
        "offline": offline,
        "dependency_source": "composer.lock",
        "dependency_count": len(dependency_results),
        "dependencies": dependency_results,
        "osv": {
            "status": "skipped" if offline else "queried",
            "source": _OSV_ENDPOINT,
            "submitted_query_count": len(unique_queries) if not offline else 0,
            "response_bytes": total_response_bytes,
            "sent_fields": ["Composer package name", "locked version"],
            "not_sent": ["project path", "source code", "composer.lock contents"],
        },
        "mysql": mysql,
        "issues": issues,
        "limitations": [
            "OSV results are advisory matches, not proof of exploitability or runtime use.",
            "Only exact package versions in composer.lock are checked; platform packages and other ecosystems are not included.",
            "A MySQL executable version may differ from the server serving the project.",
            "MySQL checks are unknown when no server binary or local NVD catalog is available.",
            "No project code is executed and no running database is contacted.",
        ],
    }
