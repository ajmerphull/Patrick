from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TextIO

from .catalog import definition_update_status
from .definition_list import list_vulnerability_definitions
from .definitions import refresh_php_definitions
from .dependencies import scan_dependencies
from .environment import (
    default_php_executable,
    scan_local_environment,
    scan_local_host,
)
from .lifecycle import refresh_php_lifecycle
from .mysql_advisories import refresh_mysql_definitions
from .scanner import (
    Rule,
    assess_runtime_version,
    load_rules,
    load_source_rules,
    scan,
    scan_source,
)
from .updates import refresh_php_releases
from .web_runtime import scan_local_web_runtime


_MODES = (
    "project",
    "source",
    "environment",
    "web-runtime",
    "device",
    "definitions",
    "dependencies",
    "list-definitions",
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="patrick",
        description=(
            "Run one clearly scoped Patrick scan mode: project, source, "
            "PHP environment, local web runtime, local device, vulnerability "
            "definition updates, a vulnerability definition list, or MySQL "
            "and Composer dependencies."
        ),
        epilog=(
            "Project, source, and dependencies modes require a project directory. "
            "List-definitions mode does not require a project directory. Environment "
            "mode requires --php-bin. Web-runtime mode requires an explicit "
            "--php-fpm-bin and/or --apache-bin. Device mode searches PHP "
            "executables in PATH. Definitions mode refreshes shared PHP-core, "
            "extension, and MySQL catalogs and sets the default PHP definition-list "
            "profile. List-definitions mode lists definitions for that PHP branch "
            "(or all branches). Dependencies mode checks composer.lock "
            "and an optional explicitly selected MySQL server executable. "
            "Use --offline to skip live PHP.net, lifecycle-data, and OSV requests."
        ),
    )
    parser.add_argument(
        "target",
        type=Path,
        nargs="?",
        help="PHP project directory (required for project, source, and dependencies modes)",
    )
    parser.add_argument(
        "--mode",
        choices=_MODES,
        default="project",
        help=(
            "project: inspect version declarations; source: scan PHP call "
            "signatures; environment: inspect one PHP binary; web-runtime: inspect "
            "explicit PHP-FPM and/or Apache binaries; device: inventory PHP "
            "binaries in local PATH; definitions: update PHP-core, extension, and MySQL advisories and set a PHP version profile; "
            "dependencies: check composer.lock and optional MySQL server; "
            "list-definitions: list local CVE definitions for a PHP branch "
            "(default: project)"
        ),
    )
    parser.add_argument(
        "--rules",
        type=Path,
        help="custom JSON runtime advisory catalog (project/environment/web-runtime modes, source preflight, or list-definitions)",
    )
    parser.add_argument(
        "--source-rules",
        type=Path,
        help="custom JSON PHP source call-signature catalog (source mode only)",
    )
    parser.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="skip live PHP.net, lifecycle-data, and OSV requests (cached lifecycle data may still be used)",
    )
    parser.add_argument(
        "--php-bin",
        type=Path,
        help="select a PHP executable (required for environment mode; overrides PATH in source mode)",
    )
    parser.add_argument(
        "--php-fpm-bin",
        type=Path,
        help="select a local PHP-FPM executable for web-runtime mode",
    )
    parser.add_argument(
        "--apache-bin",
        type=Path,
        help="select a local Apache httpd executable for web-runtime mode",
    )
    parser.add_argument(
        "--mysql-bin",
        type=Path,
        help="select a local MySQL server executable (mysqld or mariadbd) for dependencies mode",
    )
    parser.add_argument(
        "--php-version",
        help=(
            "PHP major.minor branch for the definition-list profile "
            "(for example 8.2; use 'all' for every branch)"
        ),
    )
    parser.add_argument(
        "--skip-environment-check",
        action="store_true",
        help="skip the PHP runtime preflight in source mode",
    )
    return parser


def _exit_code(report: dict[str, Any]) -> int:
    if report["mode"] == "php-vulnerability-definition-update":
        mysql_update = report.get("mysql_definition_update", {})
        return (
            0
            if report["status"] == "updated"
            and mysql_update.get("status", "updated") == "updated"
            else 3
        )

    if report["mode"] == "vulnerability-definition-list":
        return 0 if report["status"] == "complete" else 3

    if report["mode"] == "mysql-third-party-dependency-scan":
        if report["status"] == "potentially_affected":
            return 1
        return 3 if report["status"] == "unknown" else 0

    if report["mode"] == "local-php-web-runtime-scan":
        php_fpm = report["php_fpm"]
        if php_fpm is None:
            return 3
        if _runtime_has_affected(php_fpm):
            return 1
        if (
            _runtime_has_unknown(php_fpm)
            or report["issues"]
            or report["apache"] is not None
        ):
            return 3
        return 0

    if report["mode"] == "php-source-syntax-scan":
        if report["findings"]:
            return 1
        environment_check = report["environment_check"]
        if environment_check.get("assessment") == "potentially_affected":
            return 1
        if report["issues"] or report["files_scanned"] == 0:
            return 3
        if environment_check["status"] == "unavailable":
            return 3
        if environment_check.get("assessment") == "unknown":
            return 3
        return 0

    if report["mode"] == "local-host-php-inventory-scan":
        if report["issues"] or not report["executables"]:
            return 3
        return 0

    if report["mode"] == "local-php-runtime-scan":
        runtime = report["runtime"]
        if _runtime_has_affected(runtime):
            return 1
        if report["issues"] or _runtime_has_unknown(runtime):
            return 3
        return 0

    statuses = [result["status"] for result in report["results"]]
    release_statuses = [update["status"] for update in report["release_updates"]]
    lifecycle_statuses = [
        update.get("lifecycle", {}).get("status")
        for update in report["release_updates"]
    ]
    if "potentially_affected" in statuses:
        return 1
    if "end_of_life" in lifecycle_statuses:
        return 1
    if any(
        update["status"] == "update_available" and update["security_release"]
        for update in report["release_updates"]
    ):
        return 1
    if (
        report["issues"]
        or "unknown" in statuses
        or "unknown" in release_statuses
        or "unknown" in lifecycle_statuses
        or not report["declarations_found"]
    ):
        return 3
    return 0


def _runtime_has_affected(runtime: dict[str, Any]) -> bool:
    return "potentially_affected" in {
        result["status"] for result in runtime["results"]
    } or "potentially_affected" in {
        result["status"]
        for result in runtime.get("extension_assessment", {}).get("results", [])
    } or (
        runtime["release_update"]["status"] == "update_available"
        and runtime["release_update"]["security_release"]
    ) or runtime.get("release_update", {}).get("lifecycle", {}).get(
        "status"
    ) == "end_of_life"


def _runtime_has_unknown(runtime: dict[str, Any]) -> bool:
    extension_assessment = runtime.get("extension_assessment", {})
    return (
        "unknown" in {result["status"] for result in runtime["results"]}
        or runtime["release_update"]["status"] == "unknown"
        or "unknown"
        in {
            result["status"]
            for result in extension_assessment.get("results", [])
        }
        or extension_assessment.get("status") in {"unknown", "partial"}
        or runtime.get("release_update", {}).get("lifecycle", {}).get("status")
        == "unknown"
    )


def _runtime_report(
    runtime: dict[str, Any],
    rules: list[Rule],
    releases: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    assessed = assess_runtime_version(
        runtime["version"],
        runtime["binary"],
        rules,
        releases,
        runtime.get("modules"),
    )
    return {**runtime, **assessed}


def _render_text(report: dict[str, Any]) -> str:
    lines: list[str] = [f"=== {report['feature']} ==="]
    if report["mode"] == "php-source-syntax-scan":
        environment_check = report["environment_check"]
        lines.append(
            f"Environment preflight: {environment_check['status'].upper()}"
            + (
                f" ({environment_check['assessment'].replace('_', ' ')})."
                if environment_check.get("assessment")
                else "."
            )
        )
        if environment_check["status"] == "checked":
            lines.extend(_render_runtime(environment_check["runtime"]))
        for issue in environment_check["issues"]:
            lines.append(f"Environment warning: {issue}")
        for issue in report["issues"]:
            lines.append(f"Source warning: {issue}")
        for finding in report["findings"]:
            evidence = finding["evidence"]
            lines.append(
                f"{finding['severity'].upper():8} {finding['rule_id']} "
                f"{evidence['path']}:{evidence['line']}:{evidence['column']} "
                f"- {finding['summary']}"
            )
        if not report["findings"]:
            lines.append("No source call candidates found.")
        lines.append(
            f"PHP source files scanned: {report['files_scanned']}; "
            f"candidate findings: {len(report['findings'])}."
        )
        lines.extend(f"Limit: {limitation}" for limitation in report["limitations"])
    elif report["mode"] == "local-php-runtime-scan":
        lines.extend(_render_runtime(report["runtime"]))
        lines.append(f"PHP.net release check: {report['update_check']['status']}.")
        lifecycle_check = report["update_check"].get("lifecycle_check")
        if isinstance(lifecycle_check, dict):
            lines.append(
                f"PHP lifecycle data check: {lifecycle_check['status']} "
                "(endoflife.date)."
            )
    elif report["mode"] == "local-host-php-inventory-scan":
        for binary in report["executables"]:
            lines.append(f"PHP executable candidate: {binary}")
        if not report["executables"]:
            lines.append("No PHP executables were discovered in PATH.")
        lines.append(
            f"Local host PHP executable candidates: {report['executables_found']}."
        )
        lines.append(
            "Candidates were not executed; use Local PHP Runtime Scan to inspect a selected path."
        )
    elif report["mode"] == "mysql-third-party-dependency-scan":
        lines.append(
            f"Composer dependencies: {report['dependency_count']}; "
            f"OSV status: {report['osv']['status']}."
        )
        for dependency in report["dependencies"]:
            lines.append(
                f"{dependency['status'].upper():22} "
                f"{dependency['name']} {dependency['version']} "
                f"({dependency['section']}) - {dependency['reason']}"
            )
            for vulnerability in dependency["vulnerabilities"]:
                lines.append(
                    f"  {vulnerability['id']}: {vulnerability['summary']}"
                )
        mysql = report["mysql"]
        if mysql["status"] == "not_selected":
            lines.append("MySQL server: not selected.")
        elif mysql.get("version"):
            lines.append(
                f"MySQL server: {mysql['product']} {mysql['version']} "
                f"({mysql['binary']}) - {mysql['status']}."
            )
            for finding in mysql.get("findings", []):
                lines.append(f"  {finding['id']}: {finding['summary']}")
        for issue in report["issues"]:
            lines.append(f"WARNING: {issue}")
        for issue in mysql.get("issues", []):
            lines.append(f"MySQL warning: {issue}")
        lines.extend(f"Limit: {limitation}" for limitation in report["limitations"])
        return "\n".join(lines)
    elif report["mode"] == "vulnerability-definition-list":
        lines.append(
            f"Definitions available: {report['definition_count']}; "
            f"catalog status: {report['status']}."
        )
        profile = report["php_version_profile"]
        lines.append(
            f"PHP definition-list profile: "
            f"{'all PHP branches' if profile == 'all' else f'PHP {profile}'} "
            "(PHP core prioritized; extensions are best-effort and not comprehensive)."
        )
        profile_counts = report["php_profile_counts"]
        lines.append(
            f"PHP-core definitions: {profile_counts['php_core']}; "
            f"PHP extension definitions: {profile_counts['php_extensions']}."
        )
        for catalog in report["catalogs"].values():
            checked_at = catalog["checked_at"]
            included = (
                "included"
                if catalog["included_in_profile"]
                else "not included in this PHP profile"
            )
            checked_status = (
                checked_at
                if isinstance(checked_at, str) and checked_at
                else "unknown"
            )
            lines.append(
                f"Catalog: {catalog['source']} ({catalog['status']}; "
                f"checked: {checked_status}; {included})."
            )
        for definition in report["definitions"]:
            publication = definition["published_at"]
            if definition["publication_date_status"] == "missing":
                publication = "unknown (missing publication date)"
            elif definition["publication_date_status"] == "invalid":
                publication = f"invalid ({publication!r})"
            product = definition["component"]
            if definition["package_name"]:
                product += f"/{definition['package_name']}"
            severity = definition["severity"] or "unknown"
            title = definition["title"] or "title unavailable"
            lines.append(
                f"{definition['id']} | {publication} | {product} | "
                f"{severity} | {title}"
            )
        for issue in report["issues"]:
            lines.append(f"WARNING: {issue}")
        lines.extend(f"Limit: {limitation}" for limitation in report["limitations"])
        return "\n".join(lines)
    elif report["mode"] == "local-php-web-runtime-scan":
        php_fpm = report["php_fpm"]
        if php_fpm is not None:
            lines.append("PHP-FPM:")
            lines.extend(_render_runtime(php_fpm))
        else:
            lines.append("PHP-FPM: not selected or unavailable.")
        apache = report["apache"]
        if apache is not None:
            lines.append(
                f"Apache/httpd {apache['version']} ({apache['binary']})"
            )
            lines.append(
                "Loaded modules: "
                + (
                    ", ".join(apache["modules"])
                    if apache["modules"] is not None
                    else "unknown"
                )
            )
            lines.append(
                "Apache advisory assessment: not available in this release."
            )
        else:
            lines.append("Apache/httpd: not selected or unavailable.")
        lines.extend(f"WARNING: {issue}" for issue in report["issues"])
        lines.extend(f"Limit: {limitation}" for limitation in report["limitations"])
        lines.extend(_render_definition_update(report))
        return "\n".join(lines)
    elif report["mode"] == "php-vulnerability-definition-update":
        lines.append(f"Definition update status: {report['status']}.")
        profile = report.get("php_version_profile", "all")
        lines.append(
            "PHP definition-list profile set to "
            f"{'all PHP branches' if profile == 'all' else f'PHP {profile}'}; "
            "PHP core is prioritized and extension coverage is best-effort."
        )
        lines.append(
            f"NVD PHP CPE records checked: {report.get('nvd_records', 0)}; "
            f"PHP CNA records: {report.get('php_cna_records', 0)}; "
            f"PHP-core records: {report.get('php_core_records', 0)}; "
            f"PHP extension records: {report.get('php_extension_records', 0)}."
        )
        lines.append(
            f"Definitions added: {report['rules_added']}; "
            f"updated: {report['rules_updated']}; "
            f"unchanged: {report['rules_unchanged']}."
        )
        lines.append(
            f"Unmodeled PHP advisories: "
            f"{report['out_of_scope_records']}."
        )
        mysql_update = report.get("mysql_definition_update")
        if isinstance(mysql_update, dict):
            lines.append(
                f"MySQL NVD definitions: {mysql_update['status']}; "
                f"{mysql_update.get('rules', 0)} rule(s) from "
                f"{mysql_update.get('nvd_records', 0)} record(s); "
                f"{mysql_update.get('out_of_scope_records', 0)} unmodelled."
            )
            lines.extend(
                f"MySQL definition warning: {issue}"
                for issue in mysql_update.get("issues", [])
            )
        lines.append(f"Active definition cache: {report['catalog_path']}")
        for issue in report["issues"]:
            lines.append(f"WARNING: {issue}")
        lines.extend(f"Limit: {limitation}" for limitation in report["limitations"])
        return "\n".join(lines)
    else:
        return _render_project(report)

    lines.extend(_render_definition_update(report))
    for issue in report["issues"]:
        lines.append(f"WARNING: {issue}")
    for limitation in report.get("limitations", []):
        lines.append(f"Limit: {limitation}")
    return "\n".join(lines)


def _render_runtime(runtime: dict[str, Any]) -> list[str]:
    modules = runtime.get("modules")
    if modules is None:
        module_summary = "unknown"
    elif modules:
        module_summary = ", ".join(modules)
    else:
        module_summary = "none reported"
    lines = [
        f"PHP {runtime['version']} ({runtime['binary']})",
        f"Loaded modules: {module_summary}",
    ]
    for result in runtime["results"]:
        lines.append(
            f"{result['status'].upper():18} {result['rule_id']} "
            f"{result['component']} - {result['reason']}"
        )
    extension_assessment = runtime.get("extension_assessment")
    if isinstance(extension_assessment, dict):
        lines.append(
            f"Loaded extension advisory coverage: {extension_assessment['status']}."
        )
        for result in extension_assessment["results"]:
            lines.append(
                f"{result['status'].upper():18} {result['rule_id']} "
                f"{result['component']}:{result['evidence']['extension_module']} "
                f"- {result['reason']}"
            )
        without_advisories = extension_assessment["modules_without_advisories"]
        if without_advisories:
            lines.append(
                "Loaded extensions without matching advisory definitions "
                "(not assessed): " + ", ".join(without_advisories)
            )
        lines.extend(
            f"Limit: {limitation}"
            for limitation in extension_assessment.get("limitations", [])
        )
    update = runtime["release_update"]
    lines.append(f"PHP release status: {update['status']} - {update['reason']}")
    lifecycle = update.get("lifecycle")
    if isinstance(lifecycle, dict):
        lines.append(_render_lifecycle(lifecycle))
    lines.extend(f"Limit: {limitation}" for limitation in runtime["limitations"])
    return lines


def _render_lifecycle(lifecycle: dict[str, Any]) -> str:
    status = lifecycle["status"].replace("_", " ")
    line = f"PHP lifecycle: {status}"
    if lifecycle.get("branch"):
        line += f" (branch {lifecycle['branch']})"
    if lifecycle.get("support_until"):
        line += f"; active support through {lifecycle['support_until']}"
    if lifecycle.get("eol_date"):
        line += f"; end of life {lifecycle['eol_date']}"
    if lifecycle.get("latest_version"):
        line += f"; latest listed PHP release {lifecycle['latest_version']}"
        if lifecycle.get("latest_release_date"):
            line += f" ({lifecycle['latest_release_date']})"
    if lifecycle.get("lts") is True:
        line += "; LTS"
    if lifecycle.get("as_of"):
        line += f"; as of {lifecycle['as_of']}"
    line += f" - {lifecycle['reason']}"
    return line


def _render_definition_update(report: dict[str, Any]) -> list[str]:
    update = report.get("definition_update")
    if not isinstance(update, dict):
        return []
    lines = [f"PHP-core definition update status: {update['status']}."]
    if isinstance(update.get("php_core_records"), int) and isinstance(
        update.get("out_of_scope_records"), int
    ):
        extension_records = update.get("php_extension_records")
        extension_count = (
            f"; PHP extension definitions loaded: {extension_records}"
            if isinstance(extension_records, int)
            else ""
        )
        lines.append(
            f"PHP-core definitions loaded: {update['php_core_records']}; "
            f"unmodeled advisories: {update['out_of_scope_records']}"
            f"{extension_count}."
        )
    lines.extend(f"Definition warning: {issue}" for issue in update["issues"])
    return lines


def _render_project(report: dict[str, Any]) -> str:
    lines: list[str] = [f"=== {report['feature']} ==="]
    for result in report["results"]:
        evidence = result["evidence"]
        location = evidence["path"]
        if evidence["line"] is not None:
            location += f":{evidence['line']}"
        value = evidence["declared_value"] or "unresolved PHP version"
        lines.append(
            f"{result['status'].upper():18} {result['rule_id']} "
            f"{location} ({value}) - {result['reason']}"
        )
    for update in report["release_updates"]:
        evidence = update["evidence"]
        location = evidence["path"]
        if evidence["line"] is not None:
            location += f":{evidence['line']}"
        value = evidence["declared_value"] or "unresolved PHP version"
        lines.append(
            f"PHP_RELEASE_{update['status'].upper():12} {location} ({value}) "
            f"- {update['reason']}"
        )
        lifecycle = update.get("lifecycle", {})
        if lifecycle:
            lines.append(_render_lifecycle(lifecycle))
    if report["declarations_found"] == 0:
        lines.append("No supported PHP runtime declarations found; no conclusion can be drawn.")
    lines.append(f"PHP.net release check: {report['update_check']['status']}.")
    lines.extend(_render_definition_update(report))
    for issue in report["issues"]:
        lines.append(f"WARNING: {issue}")
    lines.append(
        f"Summary: {report['declarations_found']} declaration(s), "
        f"{len(report['results'])} rule result(s)."
    )
    lines.extend(f"Limit: {limitation}" for limitation in report["limitations"])
    return "\n".join(lines)


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    args = _parser().parse_args(argv)
    try:
        if args.mode in {"project", "source", "dependencies"}:
            if args.target is None:
                raise ValueError(f"--mode {args.mode} requires a project directory.")
            if not args.target.exists() or not args.target.is_dir():
                raise ValueError(f"Target must be an existing directory: {args.target}")
        elif args.target is not None:
            raise ValueError(f"--mode {args.mode} does not accept a project directory.")
        if args.php_version is not None and args.mode not in {
            "definitions",
            "list-definitions",
        }:
            raise ValueError("--php-version is only valid in definitions or list-definitions mode.")

        if args.mode == "definitions":
            if (
                args.php_bin
                or args.php_fpm_bin
                or args.apache_bin
                or args.mysql_bin
                or args.source_rules
                or args.rules
                or args.skip_environment_check
                or args.offline
            ):
                raise ValueError(
                    "Definitions mode refreshes the default catalog and does not accept scan-specific options or --offline."
                )
            report = (
                refresh_php_definitions()
                if args.php_version is None
                else refresh_php_definitions(php_version=args.php_version)
            )
            mysql_update = refresh_mysql_definitions()
            report["mysql_definition_update"] = mysql_update
            mysql_source = mysql_update.get("source")
            if isinstance(mysql_source, dict):
                report["sources"].append(
                    {
                        "name": "NVD CVE API (Oracle MySQL CPE records)",
                        "url": mysql_source.get("url"),
                        "sha256": mysql_source.get("sha256"),
                        "checked_at": mysql_source.get("checked_at"),
                    }
                )
            if mysql_update["status"] != "updated":
                report["status"] = (
                    "partial"
                    if report["status"] in {"updated", "partial"}
                    else report["status"]
                )
                report["issues"].extend(
                    f"MySQL definitions: {issue}"
                    for issue in mysql_update.get("issues", [])
                )
            report["limitations"].append(
                "MySQL advisories with complex or ambiguous NVD CPE conditions are not applied."
            )
        elif args.mode == "list-definitions":
            if (
                args.php_bin
                or args.php_fpm_bin
                or args.apache_bin
                or args.mysql_bin
                or args.source_rules
                or args.skip_environment_check
            ):
                raise ValueError(
                    "List-definitions mode accepts only an optional --rules path and --format."
                )
            report = list_vulnerability_definitions(
                args.rules, php_version=args.php_version
            )
        elif args.mode == "source":
            if args.php_fpm_bin or args.apache_bin or args.mysql_bin:
                raise ValueError(
                    "--php-fpm-bin and --apache-bin are only valid in web-runtime mode; --mysql-bin is only valid in dependencies mode."
                )
            if args.skip_environment_check and args.php_bin:
                raise ValueError(
                    "--php-bin cannot be used with --skip-environment-check."
                )
            source_rules = load_source_rules(args.source_rules)
            runtime_rules = load_rules(args.rules)
            environment_check: dict[str, Any]
            if args.skip_environment_check:
                environment_check = {
                    "status": "skipped",
                    "reason": "Skipped by --skip-environment-check.",
                    "issues": [],
                }
            else:
                php_binary = args.php_bin or default_php_executable()
                if php_binary is None:
                    environment_check = {
                        "status": "unavailable",
                        "reason": (
                            "No PHP executable named 'php' was found on PATH; "
                            "select one with --php-bin or skip with --skip-environment-check."
                        ),
                        "issues": [
                            "PHP environment preflight could not run because PHP was not found."
                        ],
                    }
                else:
                    try:
                        environment = scan_local_environment(php_binary)
                        runtime = environment["runtime"]
                        releases, update_check = _get_release_data(
                            runtime_rules,
                            args.offline,
                            runtime_versions=[runtime["version"]],
                        )
                        environment_check = {
                            "status": "checked",
                            "feature": environment["feature"],
                            "runtime": _runtime_report(runtime, runtime_rules, releases),
                            "update_check": update_check,
                            "issues": update_check["issues"],
                        }
                        assessed_runtime = environment_check["runtime"]
                        if _runtime_has_affected(assessed_runtime):
                            environment_check["assessment"] = "potentially_affected"
                        elif _runtime_has_unknown(assessed_runtime):
                            environment_check["assessment"] = "unknown"
                        else:
                            environment_check["assessment"] = "no_known_issues"
                    except ValueError as exc:
                        environment_check = {
                            "status": "unavailable",
                            "reason": str(exc),
                            "issues": [f"PHP environment preflight failed: {exc}"],
                        }

            report = scan_source(args.target, source_rules)
            report["environment_check"] = environment_check
            report["issues"].extend(environment_check["issues"])
        elif args.mode == "environment":
            if args.php_fpm_bin or args.apache_bin or args.mysql_bin:
                raise ValueError(
                    "--php-fpm-bin and --apache-bin are only valid in web-runtime mode; --mysql-bin is only valid in dependencies mode."
                )
            if args.php_bin is None:
                raise ValueError("--mode environment requires --php-bin.")
            if args.source_rules:
                raise ValueError("--source-rules is only valid in source mode.")
            if args.skip_environment_check:
                raise ValueError("--skip-environment-check is only valid in source mode.")
            rules = load_rules(args.rules)
            report = scan_local_environment(args.php_bin)
            runtime = report["runtime"]
            releases, update_check = _get_release_data(
                rules, args.offline, runtime_versions=[runtime["version"]]
            )
            report = {
                **report,
                "runtime": _runtime_report(runtime, rules, releases),
                "update_check": update_check,
                "issues": update_check["issues"],
            }
        elif args.mode == "web-runtime":
            if (
                args.php_bin
                or args.mysql_bin
                or args.source_rules
                or args.skip_environment_check
            ):
                raise ValueError(
                    "Web Runtime mode uses --php-fpm-bin and/or --apache-bin; "
                    "--php-bin, --mysql-bin, --source-rules, and --skip-environment-check are not valid."
                )
            if args.php_fpm_bin is None and args.apache_bin is None:
                raise ValueError(
                    "--mode web-runtime requires --php-fpm-bin, --apache-bin, or both."
                )
            rules = load_rules(args.rules)
            report = scan_local_web_runtime(args.php_fpm_bin, args.apache_bin)
            if report["php_fpm"] is not None:
                runtime = report["php_fpm"]
                releases, update_check = _get_release_data(
                    rules, args.offline, runtime_versions=[runtime["version"]]
                )
                assessed_runtime = _runtime_report(runtime, rules, releases)
                report["php_fpm"] = assessed_runtime
                report["update_check"] = update_check
                report["issues"].extend(update_check["issues"])
            if report["apache"] is not None:
                report["issues"].append(
                    "Apache version and modules were inventoried, but no Apache advisory catalog is available."
                )
        elif args.mode == "device":
            if (
                args.php_bin
                or args.php_fpm_bin
                or args.apache_bin
                or args.mysql_bin
                or args.source_rules
                or args.rules
                or args.skip_environment_check
                or args.offline
            ):
                raise ValueError(
                    "Device mode only discovers PHP paths; the supplied scan options are not valid."
                )
            report = scan_local_host()
        elif args.mode == "dependencies":
            if (
                args.php_bin
                or args.php_fpm_bin
                or args.apache_bin
                or args.source_rules
                or args.rules
                or args.skip_environment_check
            ):
                raise ValueError(
                    "Dependencies mode accepts only its project directory, optional --mysql-bin, and --offline."
                )
            report = scan_dependencies(
                args.target, mysql_binary=args.mysql_bin, offline=args.offline
            )
        else:
            if (
                args.php_bin
                or args.php_fpm_bin
                or args.apache_bin
                or args.mysql_bin
                or args.source_rules
                or args.skip_environment_check
            ):
                raise ValueError(
                    "Project mode does not accept PHP executable options, --source-rules, or --skip-environment-check."
                )
            rules = load_rules(args.rules)
            releases, update_check = _get_release_data(rules, args.offline)
            report = scan(args.target, rules, releases, update_check)
        if args.mode not in {
            "definitions",
            "device",
            "dependencies",
            "list-definitions",
        } and args.rules is None:
            report["definition_update"] = definition_update_status()
    except (OSError, ValueError) as exc:
        print(f"patrick: error: {exc}", file=errors)
        return 2
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True), file=output)
    else:
        print(_render_text(report), file=output)
    exit_code = _exit_code(report)
    update = report.get("definition_update")
    if (
        exit_code == 0
        and isinstance(update, dict)
        and update.get("status") in {"partial", "unavailable", "unknown"}
    ):
        return 3
    return exit_code


def _get_release_data(
    rules: list[Rule],
    offline: bool,
    runtime_versions: list[str] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    if offline:
        releases: dict[str, dict[str, Any]] = {}
        update_check = {
            "status": "skipped",
            "source": "PHP.net official release metadata",
            "issues": [
                "PHP.net update check skipped; current release status is unknown."
            ],
        }
    else:
        branches = {branch for rule in rules for branch in rule.fixed_versions}
        if runtime_versions:
            branches.update(
                ".".join(version.split(".")[:2]) for version in runtime_versions
            )
        releases, update_check = refresh_php_releases(branches)

    branches = {branch for rule in rules for branch in rule.fixed_versions}
    if runtime_versions:
        branches.update(
            ".".join(version.split(".")[:2]) for version in runtime_versions
        )
    lifecycle, lifecycle_check = refresh_php_lifecycle(branches, offline=offline)
    for branch, entry in lifecycle.items():
        releases.setdefault(branch, {})["lifecycle"] = entry
    update_check["lifecycle_check"] = lifecycle_check
    update_check["issues"].extend(lifecycle_check["issues"])
    return releases, update_check


if __name__ == "__main__":
    raise SystemExit(main())
