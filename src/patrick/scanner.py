from __future__ import annotations

import json
import re
from bisect import bisect_right
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .catalog import definition_cache_path


_EXCLUDED_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "vendor"}
_MAX_FILE_BYTES = 1_048_576
_MAX_FILES = 20_000
_VERSION_RE = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")
_IMAGE_VERSION_RE = re.compile(
    r"^(?P<version>\d+\.\d+\.\d+)(?:-(?:cli|fpm|apache|zts|alpine|bookworm|bullseye|slim)"
    r"(?:[0-9.]*)?(?:-(?:alpine|bookworm|bullseye|slim|[0-9.]+))*)?$"
)
_DOCKER_FROM_RE = re.compile(r"^\s*FROM\s+(?:(?:--platform=\S+)\s+)?(?P<image>\S+)", re.I)
_YAML_IMAGE_RE = re.compile(r"^\s*image\s*:\s*['\"]?(?P<image>[^'\"#\s]+)", re.I)
_PHP_OPEN_TAG_RE = re.compile(r"<\?(?:php\b|=|(?!(?:xml)\b))", re.I)
_HEREDOC_START_RE = re.compile(
    r"""<<<[ \t]*(?:'(?P<single>[A-Za-z_][A-Za-z0-9_]*)'|"(?P<double>[A-Za-z_][A-Za-z0-9_]*)"|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))[ \t]*\r?\n"""
)
_SOURCE_CALL_PATTERN_RE = re.compile(
    r"\s*(?P<name>\\?(?:[A-Za-z_][A-Za-z0-9_]*\\)*[A-Za-z_][A-Za-z0-9_]*)\s*\("
)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    summary: str
    component: str
    references: tuple[str, ...]
    fixed_versions: dict[str, tuple[int, int, int]]
    published_at: str | None = None
    last_modified: str | None = None
    package_name: str | None = None
    source_urls: tuple[str, ...] = ()


@dataclass(frozen=True)
class Declaration:
    path: str
    line: int | None
    kind: str
    value: str | None
    version: tuple[int, int, int] | None
    reason: str | None


def _parse_version(value: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.fullmatch(value.strip())
    if not match:
        return None
    return tuple(int(match.group(part)) for part in ("major", "minor", "patch"))


def _parse_image(image: str) -> tuple[str | None, tuple[int, int, int] | None, str | None]:
    image = image.strip().strip("\"'")
    if "$" in image:
        return image, None, "Image reference contains a variable; its resolved value is unknown."
    image_ref, digest_separator, _digest = image.partition("@")
    final_component = image_ref.rsplit("/", 1)[-1]
    image_name, separator, tag = final_component.partition(":")
    if image_name.lower() != "php":
        return None, None, None
    repository = image_ref.rsplit(":", 1)[0] if separator else image_ref
    official_names = {
        "php",
        "docker.io/php",
        "docker.io/library/php",
        "index.docker.io/php",
        "index.docker.io/library/php",
    }
    if repository.lower() not in official_names:
        return (
            tag if separator else None,
            None,
            "Non-official PHP image; image contents were not inspected.",
        )
    if digest_separator:
        return None, None, "Digest-pinned image; image contents were not inspected."
    if not separator:
        return None, None, "PHP image has no explicit version tag."

    match = _IMAGE_VERSION_RE.fullmatch(tag)
    if not match:
        return tag, None, "PHP image tag is not a recognized exact release tag."
    version_text = match.group("version")
    return version_text, _parse_version(version_text), None


def load_rules(path: Path | None = None) -> list[Rule]:
    if path is None:
        cached_path = definition_cache_path()
        data_path = (
            cached_path
            if cached_path.is_file()
            else Path(__file__).parent / "rules" / "php-runtime.json"
        )
    else:
        data_path = path
    try:
        raw: Any = json.loads(data_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read rule catalog {data_path}: {exc}") from exc

    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("Rule catalog must be an object with schema_version 1.")
    rows = raw.get("rules")
    if not isinstance(rows, list) or not rows:
        raise ValueError("Rule catalog must contain a non-empty rules array.")

    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Each rule must be a JSON object.")
        rule_id = row.get("id")
        title = row.get("title")
        severity = row.get("severity")
        summary = row.get("summary")
        component = row.get("component", "php-runtime")
        references = row.get("references")
        fixed = row.get("fixed_versions")
        published_at = row.get("published_at")
        last_modified = row.get("last_modified")
        package_name = row.get("package_name")
        source_urls = row.get("source_urls", [])
        if (
            not isinstance(rule_id, str)
            or not rule_id.strip()
            or rule_id in seen_ids
            or not isinstance(title, str)
            or not isinstance(severity, str)
            or not isinstance(summary, str)
            or not isinstance(component, str)
            or not component.strip()
            or not isinstance(references, list)
            or any(not isinstance(ref, str) for ref in references)
            or not isinstance(fixed, dict)
            or not fixed
            or (published_at is not None and not isinstance(published_at, str))
            or (last_modified is not None and not isinstance(last_modified, str))
            or (package_name is not None and not isinstance(package_name, str))
            or (
                component == "php-extension"
                and (
                    not isinstance(package_name, str)
                    or not package_name
                    or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", package_name)
                )
            )
            or not isinstance(source_urls, list)
            or any(not isinstance(url, str) for url in source_urls)
        ):
            raise ValueError("Rule has missing, invalid, or duplicate required fields.")
        fixed_versions: dict[str, tuple[int, int, int]] = {}
        for branch, release in fixed.items():
            if not isinstance(branch, str) or not isinstance(release, str):
                raise ValueError(f"Rule {rule_id} has an invalid fixed_versions entry.")
            if not re.fullmatch(r"\d+\.\d+", branch):
                raise ValueError(f"Rule {rule_id} has invalid PHP branch {branch!r}.")
            parsed = _parse_version(release)
            if parsed is None or branch != f"{parsed[0]}.{parsed[1]}":
                raise ValueError(f"Rule {rule_id} has invalid fixed release {release!r}.")
            fixed_versions[branch] = parsed
        seen_ids.add(rule_id)
        rules.append(
            Rule(
                id=rule_id,
                title=title,
                severity=severity,
                summary=summary,
                component=component,
                references=tuple(references),
                fixed_versions=fixed_versions,
                published_at=published_at,
                last_modified=last_modified,
                package_name=package_name,
                source_urls=tuple(source_urls),
            )
        )
    return rules


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def _php_image_declaration(
    root: Path, file_path: Path, line_number: int, image: str, kind: str
) -> Declaration | None:
    value, version, reason = _parse_image(image)
    if value is None and version is None and reason is None:
        return None
    return Declaration(
        path=file_path.relative_to(root).as_posix(),
        line=line_number,
        kind=kind,
        value=value,
        version=version,
        reason=reason,
    )


def _scan_dockerfile(root: Path, path: Path, text: str) -> list[Declaration]:
    results: list[Declaration] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = _DOCKER_FROM_RE.match(line)
        if match:
            declaration = _php_image_declaration(
                root, path, line_number, match.group("image"), "dockerfile"
            )
            if declaration:
                results.append(declaration)
    return results


def _scan_yaml(root: Path, path: Path, text: str) -> list[Declaration]:
    results: list[Declaration] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = _YAML_IMAGE_RE.match(line)
        if match:
            declaration = _php_image_declaration(
                root, path, line_number, match.group("image"), "yaml-image"
            )
            if declaration:
                results.append(declaration)
    return results


def _version_declaration(
    root: Path, path: Path, line: int | None, kind: str, value: str
) -> Declaration:
    parsed = _parse_version(value)
    reason = None if parsed else "Declaration is not an exact three-part PHP version."
    return Declaration(
        path=path.relative_to(root).as_posix(),
        line=line,
        kind=kind,
        value=value,
        version=parsed,
        reason=reason,
    )


def collect_declarations(root: Path) -> tuple[list[Declaration], list[str]]:
    declarations: list[Declaration] = []
    issues: list[str] = []
    visited = 0

    for current, dirs, filenames in _walk_files(root):
        dirs[:] = sorted(name for name in dirs if name not in _EXCLUDED_DIRS)
        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.is_symlink() or not path.is_file():
                continue
            visited += 1
            if visited > _MAX_FILES:
                issues.append(f"File scan limit reached ({_MAX_FILES}); scan is partial.")
                return declarations, issues

            relative = path.relative_to(root)
            is_dockerfile = filename == "Dockerfile" or filename.startswith("Dockerfile.")
            is_yaml = path.suffix.lower() in {".yaml", ".yml"}
            is_php_version = filename == ".php-version"
            is_tool_versions = filename == ".tool-versions"
            is_composer = filename == "composer.json"
            if not (is_dockerfile or is_yaml or is_php_version or is_tool_versions or is_composer):
                continue

            text = _read_text(path)
            if text is None:
                issues.append(f"Could not read supported manifest: {relative.as_posix()}")
                continue
            if is_dockerfile:
                declarations.extend(_scan_dockerfile(root, path, text))
            if is_yaml:
                declarations.extend(_scan_yaml(root, path, text))
            if is_php_version:
                value = next(
                    (line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")),
                    "",
                )
                if value:
                    declarations.append(
                        _version_declaration(root, path, 1, "php-version-file", value)
                    )
            if is_tool_versions:
                for line_number, line in enumerate(text.splitlines(), start=1):
                    parts = line.split()
                    if parts and parts[0].lower() == "php":
                        value = parts[1] if len(parts) > 1 else ""
                        declarations.append(
                            _version_declaration(root, path, line_number, "tool-versions", value)
                        )
            if is_composer:
                declarations.extend(_scan_composer(root, path, text, issues))

    return declarations, issues


def load_source_rules(path: Path | None = None) -> list[dict[str, Any]]:
    data_path = path or Path(__file__).parent / "rules" / "php-source.json"
    try:
        raw: Any = json.loads(data_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read source rule catalog {data_path}: {exc}") from exc

    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("Source rule catalog must be an object with schema_version 1.")
    rows = raw.get("rules")
    if not isinstance(rows, list) or not rows:
        raise ValueError("Source rule catalog must contain a non-empty rules array.")

    rules: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Each source rule must be a JSON object.")
        rule_id = row.get("id")
        title = row.get("title")
        severity = row.get("severity")
        summary = row.get("summary")
        pattern = row.get("pattern")
        references = row.get("references")
        case_sensitive = row.get("case_sensitive", False)
        if (
            not isinstance(rule_id, str)
            or not rule_id.strip()
            or rule_id in seen_ids
            or not isinstance(title, str)
            or not title.strip()
            or not isinstance(severity, str)
            or severity not in {"critical", "high", "medium", "low", "info"}
            or not isinstance(summary, str)
            or not summary.strip()
            or not isinstance(pattern, str)
            or not pattern
            or len(pattern.encode("utf-8")) > 256
            or not isinstance(case_sensitive, bool)
            or not isinstance(references, list)
            or any(not isinstance(reference, str) for reference in references)
        ):
            raise ValueError(
                "Source rule has missing, invalid, or duplicate required fields."
            )
        seen_ids.add(rule_id)
        rules.append(
            {
                "id": rule_id,
                "title": title,
                "severity": severity,
                "summary": summary,
                "pattern": pattern,
                "case_sensitive": case_sensitive,
                "references": references,
            }
        )
    return rules


def _blank_php_source(text: str) -> str:
    chars = list(text)
    php_mode = False
    index = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if chars[position] not in "\r\n":
                chars[position] = " "

    while index < len(text):
        if not php_mode:
            opening = _PHP_OPEN_TAG_RE.search(text, index)
            if opening is None:
                blank(index, len(text))
                break
            search_start = index
            start = opening.start()
            end = opening.end()
            blank(search_start, start)
            blank(start, end)
            index = end
            php_mode = True
            continue

        if text.startswith("?>", index):
            blank(index, index + 2)
            index += 2
            php_mode = False
            continue

        if text.startswith("//", index) or (
            text[index] == "#" and not text.startswith("#[", index)
        ):
            end = index
            while end < len(text) and text[end] not in "\r\n":
                if text.startswith("?>", end):
                    break
                end += 1
            blank(index, end)
            index = end
            continue

        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = len(text) if end < 0 else end + 2
            blank(index, end)
            index = end
            continue

        if text.startswith("<<<", index):
            heredoc = _HEREDOC_START_RE.match(text, index)
            if heredoc is not None:
                label = next(
                    value
                    for value in heredoc.group("single", "double", "bare")
                    if value is not None
                )
                body_start = heredoc.end()
                terminator_pattern = re.compile(
                    rf"(?m)^[ \t]*{re.escape(label)}(?=[ \t]*(?:[^\w \t\r\n]|$))"
                )
                terminator = terminator_pattern.search(text, body_start)
                end = len(text) if terminator is None else terminator.end()
                blank(index, end)
                index = end
                continue

        if text[index] in {"'", '"', "`"}:
            quote = text[index]
            end = index + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                    continue
                if text[end] == quote:
                    end += 1
                    break
                end += 1
            end = min(end, len(text))
            blank(index, end)
            index = end
            continue

        index += 1

    return "".join(chars)


def _source_call_matches(
    php_code: str, pattern: str, case_sensitive: bool
) -> tuple[list[re.Match[str]], bool]:
    call = _SOURCE_CALL_PATTERN_RE.fullmatch(pattern)
    flags = 0 if case_sensitive else re.IGNORECASE
    if call is None:
        return list(re.finditer(re.escape(pattern), php_code, flags)), False

    name = call.group("name").rsplit("\\", 1)[-1]
    matcher = re.compile(
        rf"(?<![\w$])\\?(?:[A-Za-z_][A-Za-z0-9_]*\\)*{re.escape(name)}\s*\(",
        flags,
    )
    matches: list[re.Match[str]] = []
    for match in matcher.finditer(php_code):
        prefix_end = match.start()
        while prefix_end and php_code[prefix_end - 1].isspace():
            prefix_end -= 1
        if php_code[max(0, prefix_end - 3) : prefix_end].endswith(
            ("?->", "->", "::")
        ):
            continue

        word_end = prefix_end
        if word_end and php_code[word_end - 1] == "&":
            word_end -= 1
            while word_end and php_code[word_end - 1].isspace():
                word_end -= 1
        word_start = word_end
        while word_start and (
            php_code[word_start - 1].isalnum() or php_code[word_start - 1] == "_"
        ):
            word_start -= 1
        previous_word = php_code[word_start:word_end]
        if previous_word.casefold() == "function":
            continue
        if previous_word.casefold() == "new":
            continue
        matches.append(match)
    return matches, True


def scan_source(root: Path, rules: list[dict[str, Any]]) -> dict[str, Any]:
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Target must be an existing directory: {root}")

    root = root.resolve()
    findings: list[dict[str, Any]] = []
    issues: list[str] = []
    visited = 0
    php_extensions = {".php", ".phtml", ".php3", ".php4", ".php5", ".inc"}
    for current, dirs, filenames in _walk_files(root):
        dirs[:] = sorted(name for name in dirs if name not in _EXCLUDED_DIRS)
        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.is_symlink() or path.suffix.lower() not in php_extensions:
                continue
            if visited >= _MAX_FILES:
                issues.append(
                    f"PHP source file scan limit reached ({_MAX_FILES}); scan is partial."
                )
                break
            visited += 1
            text = _read_text(path)
            if text is None:
                issues.append(
                    f"Could not read PHP source file: {path.relative_to(root).as_posix()}"
                )
                continue
            php_code = _blank_php_source(text)
            line_starts = [0]
            line_starts.extend(
                position + 1
                for position, character in enumerate(php_code)
                if character == "\n"
            )
            for rule in rules:
                matches, is_call_signature = _source_call_matches(
                    php_code, rule["pattern"], rule["case_sensitive"]
                )
                for match in matches:
                    line_index = bisect_right(line_starts, match.start()) - 1
                    line_number = line_index + 1
                    findings.append(
                        {
                            "rule_id": rule["id"],
                            "title": rule["title"],
                            "severity": rule["severity"],
                            "summary": rule["summary"],
                            "references": list(rule["references"]),
                            "status": "candidate",
                            "evidence": {
                                "path": path.relative_to(root).as_posix(),
                                "line": line_number,
                                "column": match.start() - line_starts[line_index] + 1,
                                "match_type": (
                                    "php-call-expression"
                                    if is_call_signature
                                    else "php-code-literal"
                                ),
                            },
                        }
                    )
        else:
            continue
        break

    return {
        "schema_version": 1,
        "feature": "PHP Source Syntax Scan",
        "mode": "php-source-syntax-scan",
        "target": str(root),
        "files_scanned": visited,
        "rules_loaded": len(rules),
        "findings": findings,
        "issues": issues,
        "limitations": [
            "The scanner lexically recognizes configured call signatures in PHP code; it is not a full PHP parser or data-flow analyzer.",
            "Findings are heuristic candidates, not proof of exploitability, and dynamic or equivalent code may be missed.",
            "Calls embedded inside interpolated strings are not analyzed.",
            "Only PHP files up to 1 MiB are read; common dependency and VCS directories are excluded.",
            "No project code was executed and no network request was made.",
        ],
    }


def _walk_files(root: Path):
    import os

    for current, dirs, filenames in os.walk(root, followlinks=False):
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in _EXCLUDED_DIRS
            and not (Path(current) / directory).is_symlink()
        ]
        yield current, dirs, filenames


def _scan_composer(
    root: Path, path: Path, text: str, issues: list[str]
) -> list[Declaration]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        issues.append(f"Invalid composer.json: {path.relative_to(root).as_posix()}")
        return []
    if not isinstance(data, dict):
        issues.append(f"Invalid composer.json root: {path.relative_to(root).as_posix()}")
        return []

    platform = data.get("config", {}).get("platform", {}) if isinstance(data.get("config"), dict) else {}
    if not isinstance(platform, dict) or "php" not in platform:
        return []
    value = platform["php"]
    if not isinstance(value, str):
        value = str(value)
    return [
        _version_declaration(
            root, path, None, "composer-platform-target", value
        )
    ]


def assess(declaration: Declaration, rule: Rule) -> dict[str, Any]:
    is_runtime_observation = declaration.kind == "local-php-runtime"
    version_subject = "Observed" if is_runtime_observation else "Declared"
    result: dict[str, Any] = {
        "rule_id": rule.id,
        "title": rule.title,
        "severity": rule.severity,
        "summary": rule.summary,
        "component": rule.component,
        "references": list(rule.references),
        "status": "unknown",
        "fixed_version": None,
        "reason": declaration.reason,
        "evidence": {
            "path": declaration.path,
            "line": declaration.line,
            "kind": declaration.kind,
            "declared_value": declaration.value,
            "php_version": ".".join(map(str, declaration.version)) if declaration.version else None,
            "authority": (
                "local-runtime-observation"
                if is_runtime_observation
                else "repository-declaration"
            ),
        },
    }
    if declaration.version is None:
        return result
    major, minor, patch = declaration.version
    branch = f"{major}.{minor}"
    fixed = rule.fixed_versions.get(branch)
    if fixed is None:
        result["reason"] = f"No fixed release is listed for PHP {branch}."
        return result
    result["fixed_version"] = ".".join(map(str, fixed))
    result["reason"] = (
        f"{version_subject} PHP {branch} release is below the first fixed release."
        if declaration.version < fixed
        else f"{version_subject} PHP {branch} release meets the listed fixed threshold."
    )
    result["status"] = "potentially_affected" if declaration.version < fixed else "fixed"
    return result


def assess_runtime_version(
    version: str,
    binary: str,
    rules: list[Rule],
    releases: dict[str, dict[str, Any]],
    modules: list[str] | None = None,
) -> dict[str, Any]:
    declaration = Declaration(
        path=binary,
        line=None,
        kind="local-php-runtime",
        value=version,
        version=_parse_version(version),
        reason=None,
    )
    runtime_rules = [rule for rule in rules if rule.component != "php-extension"]
    extension_assessment = assess_loaded_extensions(declaration, rules, modules)
    return {
        "results": [assess(declaration, rule) for rule in runtime_rules],
        "release_update": _assess_latest_release(declaration, releases),
        "extension_assessment": extension_assessment,
    }


def assess_loaded_extensions(
    declaration: Declaration,
    rules: list[Rule],
    modules: list[str] | None,
) -> dict[str, Any]:
    extension_rules = [
        rule
        for rule in rules
        if rule.component == "php-extension" and rule.package_name
    ]
    if modules is None:
        return {
            "status": "unknown",
            "loaded_modules": None,
            "modules_without_advisories": None,
            "results": [],
        }

    rules_by_module: dict[str, list[Rule]] = {}
    for rule in extension_rules:
        module_name = (rule.package_name or "").lower().removeprefix("ext-")
        if module_name:
            rules_by_module.setdefault(module_name, []).append(rule)

    results: list[dict[str, Any]] = []
    for module in modules:
        if not isinstance(module, str):
            continue
        module_rules = rules_by_module.get(
            module.lower().removeprefix("ext-"), []
        )
        for rule in module_rules:
            result = assess(declaration, rule)
            result["evidence"]["extension_module"] = module
            result["evidence"]["extension_version"] = None
            result["assessment_basis"] = "observed PHP runtime version"
            result["reason"] = (
                f"Loaded extension {module}: {result['reason']} "
                "The extension's exact build and distribution backports were not verified."
            )
            results.append(result)

    modules_without_advisories = [
        module
        for module in modules
        if isinstance(module, str)
        and module.lower().removeprefix("ext-") not in rules_by_module
    ]
    return {
        "status": "partial" if modules else "assessed",
        "loaded_modules": modules,
        "modules_without_advisories": modules_without_advisories,
        "results": results,
        "limitations": [
            "Extension versions are not independently observed; findings compare the PHP runtime release with the advisory's PHP release threshold.",
            "Distribution backports and separately installed builds may change extension applicability.",
        ],
    }


def _assess_latest_release(
    declaration: Declaration, releases: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    branch = (
        ".".join(str(part) for part in declaration.version[:2])
        if declaration.version is not None
        else None
    )
    lifecycle = _assess_php_lifecycle(
        declaration,
        releases.get(branch, {}).get("lifecycle") if branch else None,
    )
    result: dict[str, Any] = {
        "status": "unknown",
        "reason": declaration.reason or "No exact declared PHP version is available.",
        "latest_version": None,
        "latest_release_date": None,
        "security_release": None,
        "lifecycle": lifecycle,
        "evidence": {
            "path": declaration.path,
            "line": declaration.line,
            "kind": declaration.kind,
            "declared_value": declaration.value,
        },
    }
    if declaration.version is None:
        return result

    major, minor, _patch = declaration.version
    release = releases.get(f"{major}.{minor}")
    if release is None or not isinstance(release.get("version"), str):
        result["reason"] = "No PHP.net release metadata is available for this branch."
        return result
    if not release["supported"]:
        result["reason"] = "PHP.net does not list this branch as currently supported."
        return result

    latest = tuple(int(part) for part in release["version"].split("."))
    version_subject = (
        "Observed" if declaration.kind == "local-php-runtime" else "Declared"
    )
    result.update(
        {
            "status": "update_available" if declaration.version < latest else "current",
            "reason": (
                f"PHP {release['version']} is the latest listed release for this branch; "
                f"the {version_subject.lower()} version is older."
                if declaration.version < latest
                else f"{version_subject} version meets or exceeds the latest listed branch release."
            ),
            "latest_version": release["version"],
            "latest_release_date": release["date"],
            "security_release": release["security_release"],
            "source_url": release["source_url"],
            "source_checked_at": release["checked_at"],
        }
    )
    return result


def _assess_php_lifecycle(
    declaration: Declaration, lifecycle: dict[str, Any] | None
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "reason": declaration.reason or "No exact PHP branch is available.",
        "branch": None,
        "support_until": None,
        "eol_date": None,
        "latest_version": None,
        "latest_release_date": None,
        "lts": None,
        "source_url": None,
        "source_checked_at": None,
        "as_of": datetime.now(timezone.utc).date().isoformat(),
    }
    if declaration.version is None:
        return result
    branch = ".".join(str(part) for part in declaration.version[:2])
    result["branch"] = branch
    if lifecycle is None:
        result["reason"] = f"No PHP lifecycle metadata is available for branch {branch}."
        return result

    support_until = lifecycle.get("support_date")
    eol_date = lifecycle.get("eol_date")
    result.update(
        {
            "support_until": support_until,
            "eol_date": eol_date,
            "latest_version": lifecycle.get("latest_version"),
            "latest_release_date": lifecycle.get("latest_release_date"),
            "lts": lifecycle.get("lts"),
            "source_url": lifecycle.get("source_url"),
            "source_checked_at": lifecycle.get("checked_at"),
        }
    )
    today = datetime.now(timezone.utc).date()
    end_of_life = (
        datetime.strptime(eol_date, "%Y-%m-%d").date()
        if isinstance(eol_date, str)
        else None
    )
    if end_of_life is not None and today > end_of_life:
        status = "end_of_life"
        reason = f"PHP {branch} reached end of life on {eol_date}."
    elif not isinstance(support_until, str):
        result["reason"] = f"PHP lifecycle support date for branch {branch} is unknown."
        return result
    elif today <= datetime.strptime(support_until, "%Y-%m-%d").date():
        status = "active_support"
        reason = f"PHP {branch} is in active support through {support_until}."
    elif end_of_life is None:
        result["reason"] = (
            f"PHP lifecycle end-of-life date for branch {branch} is unknown."
        )
        return result
    else:
        status = "security_maintenance"
        reason = (
            f"PHP {branch} is in security maintenance through {eol_date}; "
            f"active support ended {support_until}."
        )
    result.update({"status": status, "reason": reason})
    return result


def scan(
    root: Path,
    rules: list[Rule],
    latest_releases: dict[str, dict[str, Any]] | None = None,
    update_check: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Target must be an existing directory: {root}")
    declarations, issues = collect_declarations(root.resolve())
    latest_releases = latest_releases or {}
    runtime_rules = [rule for rule in rules if rule.component != "php-extension"]
    findings = [
        assess(declaration, rule)
        for declaration in declarations
        for rule in runtime_rules
    ]
    release_updates = [
        _assess_latest_release(declaration, latest_releases)
        for declaration in declarations
    ]
    if update_check:
        issues.extend(update_check.get("issues", []))
    return {
        "schema_version": 1,
        "feature": "Project Version Declaration Scan",
        "mode": "project-version-declaration-scan",
        "target": str(root.resolve()),
        "declarations_found": len(declarations),
        "results": findings,
        "release_updates": release_updates,
        "update_check": update_check
        or {
            "status": "not_checked",
            "source": "PHP.net official release metadata",
            "issues": [],
        },
        "issues": issues,
        "limitations": [
            "Repository declarations do not prove which PHP binary serves production traffic.",
            "PHP release checks report latest releases, not whether a PHP installation is running.",
            "PHP release metadata does not enumerate every vulnerability; CVE rules remain curated.",
            "Project declarations cannot establish which PHP extensions are installed or loaded.",
            "No application code was executed.",
        ],
    }
