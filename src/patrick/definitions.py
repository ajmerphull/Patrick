from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from .catalog import definition_cache_path
from .php_version_profile import normalize_php_version_profile


_NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_CPE = "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"
_NVD_PAGE_SIZE = 2000
_MAX_NVD_RESULTS = 10_000
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_MAX_GHSA_BYTES = 2 * 1024 * 1024
_REQUEST_TIMEOUT_SECONDS = 12
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
_BRANCH_VERSION_RE = re.compile(r"^(?P<branch>\d+\.\d+)\.(?:\*|x)$")
_EXACT_BRANCH_START_RE = re.compile(r"^(?P<branch>\d+\.\d+)\.0$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_CORE_PACKAGE_NAMES = {"php-src"}
_EXTENSION_PACKAGE_RE = re.compile(r"^(?:ext-)?[a-z][a-z0-9_]{0,62}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _AdvisoryPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sections: dict[str, list[str]] = {
            "affected versions": [],
            "patched versions": [],
        }
        self.text: list[str] = []
        self._heading: list[str] | None = None
        self._section: str | None = None
        self._value: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "h2":
            self._heading = []
            self._section = None
        elif tag == "div" and self._section in self.sections:
            classes = set((attributes.get("class") or "").split())
            if "f4" in classes:
                self._value = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "h2" and self._heading is not None:
            heading = " ".join("".join(self._heading).split()).lower()
            self._section = heading if heading in self.sections else None
            self._heading = None
        elif tag == "div" and self._value is not None:
            value = " ".join("".join(self._value).split())
            if value and self._section is not None:
                self.sections[self._section].append(value)
            self._value = None

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self._heading is not None:
            self._heading.append(data)
        if self._value is not None:
            self._value.append(data)


def _parse_fixed_versions(values: list[str]) -> dict[str, str]:
    versions: dict[str, str] = {}
    for value in values:
        if not _VERSION_RE.fullmatch(value):
            continue
        branch = ".".join(value.split(".")[:2])
        previous = versions.get(branch)
        if previous is not None and previous != value:
            raise ValueError(f"Multiple patched versions were declared for PHP {branch}.")
        versions[branch] = value
    if not versions:
        raise ValueError("No exact patched PHP versions were found in the advisory.")
    return versions


def parse_github_advisory(
    html: str, *, ghsa_id: str, cve_id: str
) -> tuple[dict[str, str], str]:
    if not _GHSA_RE.fullmatch(ghsa_id) or not _CVE_RE.fullmatch(cve_id):
        raise ValueError("Invalid GitHub advisory or CVE identifier.")
    parser = _AdvisoryPageParser()
    parser.feed(html)
    page_text = " ".join(" ".join(parser.text).split())
    if ghsa_id not in page_text or cve_id not in page_text:
        raise ValueError("GitHub advisory identity did not match the NVD record.")
    fixed_versions = _parse_fixed_versions(parser.sections["patched versions"])
    return fixed_versions, hashlib.sha256(html.encode("utf-8")).hexdigest()


def _fetch_github_advisory(url: str, *, ghsa_id: str, cve_id: str) -> dict[str, Any]:
    expected_path = f"/php/php-src/security/advisories/{ghsa_id}"
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("PHP-src advisory reference is not an allowed GitHub URL.")
    request = Request(
        url,
        headers={
            "Accept": "text/html",
            "User-Agent": "Patrick/0.1",
        },
    )
    try:
        with urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            final_url = urlsplit(response.geturl())
            if (
                final_url.scheme != "https"
                or final_url.hostname != "github.com"
                or final_url.path != expected_path
            ):
                raise ValueError("GitHub advisory redirected outside its expected page.")
            raw = response.read(_MAX_GHSA_BYTES + 1)
    except (OSError, URLError, TimeoutError) as exc:
        raise ValueError(f"Unable to fetch {ghsa_id}: {exc}") from exc

    if len(raw) > _MAX_GHSA_BYTES:
        raise ValueError(f"{ghsa_id} advisory page exceeds the size limit.")
    try:
        html = raw.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{ghsa_id} advisory page is not valid UTF-8.") from exc
    fixed_versions, digest = parse_github_advisory(
        html, ghsa_id=ghsa_id, cve_id=cve_id
    )
    return {
        "fixed_versions": fixed_versions,
        "sha256": digest,
        "checked_at": _now(),
    }


def _fetch_nvd_cves_for_cpe(
    cpe: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    start_index = 0
    total_results: int | None = None
    while total_results is None or start_index < total_results:
        if start_index:
            time.sleep(6)
        query = urlencode(
            {
                "virtualMatchString": cpe,
                "resultsPerPage": _NVD_PAGE_SIZE,
                "startIndex": start_index,
            }
        )
        request = Request(
            f"{_NVD_ENDPOINT}?{query}",
            headers={
                "Accept": "application/json",
                "User-Agent": "Patrick/0.1",
            },
        )
        try:
            with urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
                final_url = urlsplit(response.geturl())
                if (
                    final_url.scheme != "https"
                    or final_url.hostname != "services.nvd.nist.gov"
                ):
                    raise ValueError("NVD endpoint redirected outside services.nvd.nist.gov.")
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except (OSError, URLError, TimeoutError) as exc:
            raise ValueError(f"Unable to fetch NVD CPE vulnerability records: {exc}") from exc

        if len(raw) > _MAX_RESPONSE_BYTES:
            raise ValueError("NVD response exceeded the configured size limit.")
        digest.update(raw)
        try:
            data: Any = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("NVD response is not valid UTF-8 JSON.") from exc
        if (
            not isinstance(data, dict)
            or data.get("format") != "NVD_CVE"
            or not isinstance(data.get("totalResults"), int)
            or not isinstance(data.get("startIndex"), int)
            or data["startIndex"] != start_index
            or not isinstance(data.get("vulnerabilities"), list)
        ):
            raise ValueError("NVD response failed structural validation.")
        if total_results is None:
            total_results = data["totalResults"]
            if total_results > _MAX_NVD_RESULTS:
                raise ValueError(
                    f"NVD CPE results exceed the {_MAX_NVD_RESULTS} record limit."
                )
        page_rows = data["vulnerabilities"]
        if not page_rows:
            if start_index < total_results:
                raise ValueError("NVD returned an incomplete paged response.")
            break
        for row in page_rows:
            if not isinstance(row, dict) or not isinstance(row.get("cve"), dict):
                raise ValueError("NVD response contains an invalid CVE row.")
            rows.append(row["cve"])
        start_index += len(page_rows)
        if start_index < total_results and len(page_rows) < _NVD_PAGE_SIZE:
            raise ValueError("NVD returned a short page before the result set ended.")

    return rows, {
        "url": f"{_NVD_ENDPOINT}?virtualMatchString={cpe}",
        "sha256": digest.hexdigest(),
        "records": len(rows),
        "checked_at": _now(),
    }


def _fetch_nvd_cves() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return _fetch_nvd_cves_for_cpe(_NVD_CPE)


def _affected_php_rule(cve: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not _CVE_RE.fullmatch(cve_id):
        raise ValueError("NVD record has an invalid CVE identifier.")
    if cve.get("sourceIdentifier") != "security@php.net":
        return None
    if cve.get("vulnStatus") == "Rejected":
        return None

    affected = cve.get("affected")
    if not isinstance(affected, list):
        raise ValueError(f"{cve_id} is missing the CNA affected-version data.")
    package_records: list[dict[str, Any]] = []
    for source_record in affected:
        if not isinstance(source_record, dict):
            raise ValueError(f"{cve_id} contains malformed affected-version data.")
        if source_record.get("source") != "security@php.net":
            continue
        affected_data = source_record.get("affectedData")
        if not isinstance(affected_data, list):
            raise ValueError(f"{cve_id} contains malformed PHP CNA data.")
        package_records.extend(
            row
            for row in affected_data
            if isinstance(row, dict)
            and row.get("vendor") == "PHP Group"
            and row.get("product") == "PHP"
            and (
                row.get("packageName") in _CORE_PACKAGE_NAMES
                or (
                    isinstance(row.get("packageName"), str)
                    and _EXTENSION_PACKAGE_RE.fullmatch(row["packageName"])
                    and row["packageName"].lower() not in {"php", "php-src"}
                )
            )
        )
    if not package_records:
        return None
    package_names = {row["packageName"].lower() for row in package_records}
    if len(package_names) != 1:
        raise ValueError(
            f"{cve_id} affects multiple PHP packages Patrick cannot model safely."
        )
    package_name = next(iter(package_names))
    is_core = package_name in _CORE_PACKAGE_NAMES

    fixed_versions: dict[str, str] = {}
    for package_record in package_records:
        versions = package_record.get("versions")
        if not isinstance(versions, list):
            raise ValueError(f"{cve_id} has no structured PHP version ranges.")
        for version in versions:
            if not isinstance(version, dict):
                raise ValueError(f"{cve_id} contains a malformed PHP version range.")
            state = version.get("status")
            if state not in {"affected", "unaffected"}:
                raise ValueError(f"{cve_id} contains an unsupported PHP range status.")
            if state == "unaffected":
                continue
            declared_version = (
                version.get("version")
                if isinstance(version.get("version"), str)
                else ""
            )
            branch_match = _BRANCH_VERSION_RE.fullmatch(declared_version)
            if branch_match is None:
                branch_match = _EXACT_BRANCH_START_RE.fullmatch(declared_version)
            fixed = version.get("lessThan")
            if (
                version.get("versionType") != "semver"
                or branch_match is None
                or not isinstance(fixed, str)
                or not _VERSION_RE.fullmatch(fixed)
                or ".".join(fixed.split(".")[:2]) != branch_match.group("branch")
                or version.get("lessThanOrEqual") is not None
            ):
                raise ValueError(
                    f"{cve_id} has an affected PHP range Patrick cannot model safely."
                )
            branch = branch_match.group("branch")
            if branch in fixed_versions and fixed_versions[branch] != fixed:
                raise ValueError(
                    f"{cve_id} has conflicting fixed versions for PHP {branch}."
                )
            fixed_versions[branch] = fixed
    if not fixed_versions:
        raise ValueError(f"{cve_id} has no exact PHP-core fixed-version thresholds.")

    descriptions = cve.get("descriptions")
    summary = None
    if isinstance(descriptions, list):
        summary = next(
            (
                row.get("value")
                for row in descriptions
                if isinstance(row, dict)
                and row.get("lang") == "en"
                and isinstance(row.get("value"), str)
                and row["value"].strip()
            ),
            None,
        )
    published_at = cve.get("published")
    last_modified = cve.get("lastModified")
    if (
        not isinstance(summary, str)
        or not isinstance(published_at, str)
        or not isinstance(last_modified, str)
    ):
        raise ValueError(f"{cve_id} is missing its description or timestamps.")
    for timestamp in (published_at, last_modified):
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"{cve_id} contains an invalid timestamp.") from exc

    references = cve.get("references")
    if not isinstance(references, list):
        raise ValueError(f"{cve_id} is missing references.")
    github_urls: set[str] = set()
    for reference in references:
        if not isinstance(reference, dict) or not isinstance(reference.get("url"), str):
            continue
        ref_url = reference["url"]
        if "/php/php-src/security/advisories/" in ref_url:
            ref_parts = urlsplit(ref_url)
            ghsa_id = ref_parts.path.rsplit("/", 1)[-1]
            if (
                ref_parts.scheme != "https"
                or ref_parts.hostname != "github.com"
                or ref_parts.path
                != f"/php/php-src/security/advisories/{ghsa_id}"
                or not _GHSA_RE.fullmatch(ghsa_id)
            ):
                raise ValueError(f"{cve_id} contains an invalid PHP-src advisory URL.")
            github_urls.add(ref_url)
    if len(github_urls) > 1:
        raise ValueError(f"{cve_id} references multiple PHP-src advisories.")
    github_url = next(iter(github_urls), None)

    severity = "unknown"
    metrics = cve.get("metrics")
    if isinstance(metrics, dict):
        scores: list[tuple[float, str]] = []
        for metric_rows in metrics.values():
            if not isinstance(metric_rows, list):
                continue
            for metric in metric_rows:
                if not isinstance(metric, dict):
                    continue
                if metric.get("source") != "security@php.net":
                    continue
                cvss_data = metric.get("cvssData")
                if not isinstance(cvss_data, dict):
                    continue
                score = cvss_data.get("baseScore")
                if isinstance(score, (int, float)):
                    scores.append((float(score), str(cvss_data.get("baseSeverity", ""))))
        if scores:
            score, source_severity = max(scores, key=lambda row: row[0])
            if source_severity.lower() in {"critical", "high", "medium", "low"}:
                severity = source_severity.lower()
            elif score >= 9:
                severity = "critical"
            elif score >= 7:
                severity = "high"
            elif score >= 4:
                severity = "medium"
            else:
                severity = "low"

    title = summary.split(". ", 1)[0].strip()
    if len(title) > 180:
        title = title[:177].rstrip() + "..."
    result: dict[str, Any] = {
        "id": cve_id,
        "title": title or cve_id,
        "severity": severity,
        "component": "php-core" if is_core else "php-extension",
        "summary": summary.strip(),
        "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        "fixed_versions": fixed_versions,
        "published_at": published_at,
        "last_modified": last_modified,
        "package_name": "php-src" if is_core else package_name.removeprefix("ext-"),
        "source_urls": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
    }
    if github_url:
        result["references"].append(github_url)
        result["source_urls"].append(github_url)
    return result


def _save_catalog(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=2, sort_keys=True)
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


def refresh_php_definitions(
    *, cache_file: Path | None = None, php_version: str | None = None
) -> dict[str, Any]:
    """Update the local PHP-core catalog from NVD CNA data and linked PHP advisories."""
    normalized_php_version = normalize_php_version_profile(php_version)
    cache_file = cache_file or definition_cache_path()
    bundled_file = Path(__file__).parent / "rules" / "php-runtime.json"
    current_file = cache_file if cache_file.exists() else bundled_file
    try:
        from .scanner import load_rules

        load_rules(current_file)
        catalog: Any = json.loads(current_file.read_text(encoding="utf-8"))
        cves, nvd_source = _fetch_nvd_cves()
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return {
            "schema_version": 1,
            "feature": "PHP Vulnerability Definition Update",
            "mode": "php-vulnerability-definition-update",
            "status": "unavailable",
            "checked_at": _now(),
            "catalog_path": str(cache_file),
            "php_version_profile": normalized_php_version or "all",
            "rules_added": 0,
            "rules_updated": 0,
            "rules_unchanged": 0,
            "out_of_scope_records": 0,
            "issues": [str(exc)],
            "sources": [],
        }

    existing_rows = catalog["rules"]
    by_id = {row["id"]: row for row in existing_rows}
    candidates: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    issues: list[str] = []
    out_of_scope = 0
    core_records = 0
    extension_records = 0
    php_cna_records = 0
    seen_cves: set[str] = set()
    existing_php_ids = {
        row["id"]
        for row in existing_rows
        if row.get("component") in {"php-core", "php-extension"}
        and isinstance(row.get("id"), str)
        and _CVE_RE.fullmatch(row["id"])
    }

    for cve in cves:
        record_id = cve.get("id")
        cve_id = (
            record_id
            if isinstance(record_id, str) and _CVE_RE.fullmatch(record_id)
            else None
        )
        if cve_id is not None and cve_id in seen_cves:
            issues.append(f"{cve_id} appeared more than once in the NVD result set.")
            continue
        if cve_id is not None:
            seen_cves.add(cve_id)
        if cve.get("sourceIdentifier") != "security@php.net":
            if cve_id in existing_php_ids:
                issues.append(
                    f"{cve_id} no longer identifies security@php.net as its CNA; "
                    "the existing rule was retained."
                )
            continue
        php_cna_records += 1
        if cve.get("vulnStatus") == "Rejected":
            if cve_id in existing_php_ids:
                issues.append(
                    f"{cve_id} is rejected in NVD; the existing rule was retained."
                )
            else:
                out_of_scope += 1
            continue
        try:
            candidate = _affected_php_rule(cve)
            if candidate is None:
                out_of_scope += 1
                if cve_id in existing_php_ids:
                    issues.append(
                        f"{cve_id} no longer declares a supported PHP package; "
                        "the existing rule was retained."
                    )
                continue
            github_url = next(
                (
                    url
                    for url in candidate["source_urls"]
                    if url.startswith("https://github.com/php/php-src/security/advisories/")
                ),
                None,
            )
            github_record = None
            if github_url:
                ghsa_id = github_url.rsplit("/", 1)[-1]
                github_record = _fetch_github_advisory(
                    github_url, ghsa_id=ghsa_id, cve_id=candidate["id"]
                )
                if github_record["fixed_versions"] != candidate["fixed_versions"]:
                    raise ValueError(
                        f"{candidate['id']} has conflicting NVD and PHP-src fixed versions."
                    )
                candidate["source_digests"] = [
                    {
                        "url": github_url,
                        "sha256": github_record["sha256"],
                        "checked_at": github_record["checked_at"],
                    }
                ]
            candidate["source_digests"] = [
                {
                    "url": nvd_source["url"],
                    "sha256": nvd_source["sha256"],
                    "checked_at": nvd_source["checked_at"],
                },
                *candidate.get("source_digests", []),
            ]
            candidates.append((candidate, by_id.get(candidate["id"])))
            if candidate["component"] == "php-core":
                core_records += 1
            else:
                extension_records += 1
        except ValueError as exc:
            issues.append(str(exc))

    for rule_id in sorted(existing_php_ids - seen_cves):
        issues.append(
            f"{rule_id} was not returned by the complete NVD PHP CPE query; "
            "the existing rule was retained."
        )
    if php_cna_records == 0:
        issues.append(
            "The NVD PHP CPE response contained no security@php.net CNA records."
        )
    if php_cna_records and not candidates and not issues:
        issues.append(
            "The NVD response contained no validated PHP-core or PHP extension "
            "records; no definition update was applied."
        )

    additions = updates = unchanged = 0
    for candidate, existing in candidates:
        if existing is None:
            existing_rows.append(candidate)
            by_id[candidate["id"]] = candidate
            additions += 1
        elif any(
            existing.get(key) != candidate.get(key)
            for key in (
                "title",
                "severity",
                "component",
                "summary",
                "references",
                "fixed_versions",
                "published_at",
                "last_modified",
                "package_name",
                "source_urls",
            )
        ):
            existing.update(candidate)
            updates += 1
        else:
            existing.update(
                {
                    "source_digests": candidate.get("source_digests", []),
                    "last_modified": candidate["last_modified"],
                    "published_at": candidate["published_at"],
                    "package_name": candidate["package_name"],
                    "source_urls": candidate["source_urls"],
                }
            )
            unchanged += 1

    status = "updated" if not issues else "partial"
    catalog["update_metadata"] = {
        "status": status,
        "checked_at": _now(),
        "sources": [nvd_source],
        "php_cna_records": php_cna_records,
        "php_core_records": core_records,
        "php_extension_records": extension_records,
        "out_of_scope_records": out_of_scope,
        "php_version_profile": normalized_php_version or "all",
        "issues": issues,
    }
    try:
        _save_catalog(cache_file, catalog)
    except OSError as exc:
        issues.append(f"Could not save updated definition catalog: {exc}")
        status = "partial"

    return {
        "schema_version": 1,
        "feature": "PHP Vulnerability Definition Update",
        "mode": "php-vulnerability-definition-update",
        "status": status,
        "checked_at": catalog["update_metadata"]["checked_at"],
        "catalog_path": str(cache_file),
        "nvd_records": nvd_source["records"],
        "php_cna_records": php_cna_records,
        "php_core_records": core_records,
        "php_extension_records": extension_records,
        "rules_added": additions,
        "rules_updated": updates,
        "rules_unchanged": unchanged,
        "out_of_scope_records": out_of_scope,
        "php_version_profile": normalized_php_version or "all",
        "sources": [
            {
                "name": "NVD CVE API (PHP CNA records)",
                "url": nvd_source["url"],
                "sha256": nvd_source["sha256"],
                "checked_at": nvd_source["checked_at"],
            },
            "PHP-src GitHub advisories linked by NVD records",
        ],
        "issues": issues,
        "limitations": [
            "Only records authored by security@php.net with supported PHP-core or named PHP extension packages and exact PHP release thresholds are applied.",
            "Linked PHP-src advisory thresholds must exactly match NVD; conflicts and unparseable records are not applied.",
            "Extension advisories are matched to loaded PHP module names; the exact extension build and distribution backports are not independently verified.",
            "The selected PHP version profile filters the definition-list view; the shared catalog continues to retain definitions for every supported PHP branch.",
            "Extension coverage is best-effort and does not include every PHP extension vulnerability.",
            "An absent advisory from NVD does not prove that no PHP vulnerability exists.",
        ],
    }
