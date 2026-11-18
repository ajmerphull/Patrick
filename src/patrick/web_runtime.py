from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any


_PHP_VERSION_RE = re.compile(r"PHP (?P<version>\d+\.\d+\.\d+)", re.IGNORECASE)
_APACHE_VERSION_RE = re.compile(r"Apache/(?P<version>\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_TIMEOUT_SECONDS = 5


def _validate_executable(binary: Path) -> Path:
    resolved = binary.expanduser().resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError(f"Executable is not an executable file: {resolved}")
    return resolved


def _run(binary: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [str(binary), *args],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"Could not inspect executable {binary}: {exc}") from exc


def _successful_output(
    binary: Path, args: list[str]
) -> subprocess.CompletedProcess[str]:
    result = _run(binary, args)
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or result.stdout.strip()
        raise ValueError(
            f"{binary} {' '.join(args)} returned {result.returncode}: {diagnostic}"
        )
    return result


def inspect_php_fpm(binary: Path) -> dict[str, Any]:
    binary = _validate_executable(binary)
    version_result = _successful_output(binary, ["-v"])
    version_match = _PHP_VERSION_RE.search(version_result.stdout)
    if version_match is None:
        raise ValueError(f"Could not parse PHP-FPM version from {binary} -v.")

    module_result = _run(binary, ["-m"])
    modules: list[str] | None = None
    issues: list[str] = []
    if module_result.returncode == 0:
        modules = [
            line.strip()
            for line in module_result.stdout.splitlines()
            if line.strip() and not line.startswith("[")
        ]
    else:
        diagnostic = module_result.stderr.strip() or module_result.stdout.strip()
        issues.append(f"Could not inspect PHP-FPM modules: {diagnostic}")

    return {
        "binary": str(binary),
        "version": version_match.group("version"),
        "sapi": "PHP-FPM executable",
        "modules": modules,
        "commands": ["-v", "-m"],
        "issues": issues,
        "limitations": [
            "The selected executable was inspected; no running FPM process or pool configuration was verified.",
            "PHP-FPM startup configuration may affect module output; application code was not invoked.",
        ],
    }


def inspect_apache(binary: Path) -> dict[str, Any]:
    binary = _validate_executable(binary)
    version_result = _successful_output(binary, ["-v"])
    version_match = _APACHE_VERSION_RE.search(version_result.stdout)
    if version_match is None:
        raise ValueError(f"Could not parse Apache version from {binary} -v.")

    module_result = _run(binary, ["-M"])
    modules: list[str] | None = None
    issues: list[str] = []
    if module_result.returncode == 0:
        module_output = f"{module_result.stdout}\n{module_result.stderr}"
        modules = sorted(
            set(
                re.findall(
                    r"^\s*([A-Za-z0-9_]+_module)\s+\((?:static|shared)\)\s*$",
                    module_output,
                    re.MULTILINE,
                )
            )
        )
        if not modules:
            issues.append("Apache -M returned no recognizable module declarations.")
    else:
        diagnostic = module_result.stderr.strip() or module_result.stdout.strip()
        issues.append(f"Could not inspect Apache modules: {diagnostic}")

    return {
        "binary": str(binary),
        "version": version_match.group("version"),
        "modules": modules,
        "commands": ["-v", "-M"],
        "issues": issues,
        "limitations": [
            "Apache -M reads the selected installation's configuration; it does not verify a running server or its active configuration.",
            "Apache version and modules are inventory only; this release has no Apache vulnerability catalog.",
        ],
    }


def scan_local_web_runtime(
    php_fpm_binary: Path | None, apache_binary: Path | None
) -> dict[str, Any]:
    php_fpm: dict[str, Any] | None = None
    apache: dict[str, Any] | None = None
    issues: list[str] = []

    if php_fpm_binary is not None:
        try:
            php_fpm = inspect_php_fpm(php_fpm_binary)
            issues.extend(php_fpm["issues"])
        except ValueError as exc:
            issues.append(f"PHP-FPM inspection unavailable: {exc}")

    if apache_binary is not None:
        try:
            apache = inspect_apache(apache_binary)
            issues.extend(apache["issues"])
        except ValueError as exc:
            issues.append(f"Apache inspection unavailable: {exc}")

    return {
        "schema_version": 1,
        "feature": "Local PHP Web Runtime Scan",
        "mode": "local-php-web-runtime-scan",
        "php_fpm": php_fpm,
        "apache": apache,
        "issues": issues,
        "limitations": [
            "Only explicitly selected local executables are inspected; no remote host or endpoint is contacted.",
            "Executable version output does not prove which binary or configuration serves project traffic.",
        ],
    }
