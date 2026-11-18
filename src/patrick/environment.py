from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


_VERSION_RE = re.compile(r"PHP (?P<version>\d+\.\d+\.\d+)", re.IGNORECASE)
_TIMEOUT_SECONDS = 5


def default_php_executable() -> Path | None:
    found = shutil.which("php")
    return Path(found) if found else None


def _run_php(binary: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(
            [str(binary), *args],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"Could not inspect PHP executable {binary}: {exc}") from exc
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or result.stdout.strip()
        raise ValueError(
            f"PHP executable {binary} returned {result.returncode}: {diagnostic}"
        )
    return result.stdout


def inspect_php_runtime(binary: Path) -> dict[str, Any]:
    binary = binary.expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError(f"PHP executable is not an executable file: {binary}")

    version_output = _run_php(binary, ["--version"])
    version_match = _VERSION_RE.search(version_output)
    if version_match is None:
        raise ValueError(f"Could not parse PHP version from {binary} --version.")

    module_output = _run_php(binary, ["-m"])
    modules = [
        line.strip()
        for line in module_output.splitlines()
        if line.strip() and not line.startswith("[")
    ]
    ini_output = _run_php(binary, ["--ini"])
    loaded_ini = None
    scanned_ini = None
    for line in ini_output.splitlines():
        if line.startswith("Loaded Configuration File:"):
            loaded_ini = line.partition(":")[2].strip()
        elif line.startswith("Scan for additional .ini files in:"):
            scanned_ini = line.partition(":")[2].strip()

    return {
        "binary": str(binary),
        "version": version_match.group("version"),
        "sapi": "CLI executable",
        "modules": modules,
        "loaded_configuration": loaded_ini,
        "additional_ini_directory": scanned_ini,
        "commands": ["--version", "-m", "--ini"],
        "limitations": [
            "This inspects one CLI executable; it does not establish FPM, Apache, or production runtime state.",
            "PHP startup may load configured extensions; application code is not invoked.",
        ],
    }


def discover_php_executables() -> list[Path]:
    names = {"php", "php.exe", "php8", "php7", "php8.exe", "php7.exe"}
    names.update(
        f"php{major}.{minor}"
        for major in range(7, 10)
        for minor in range(0, 10)
    )
    if os.name == "nt":
        names.add("php-cgi.exe")

    discovered: dict[str, Path] = {}
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        directory = Path(entry).expanduser()
        for name in names:
            candidate = directory / name
            try:
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    resolved = candidate.resolve()
                    discovered[str(resolved)] = resolved
            except OSError:
                continue
    return [discovered[key] for key in sorted(discovered)]


def scan_local_environment(binary: Path) -> dict[str, Any]:
    runtime = inspect_php_runtime(binary)
    return {
        "schema_version": 1,
        "feature": "Local PHP Runtime Scan",
        "mode": "local-php-runtime-scan",
        "runtime": runtime,
        "issues": [],
    }


def scan_local_host() -> dict[str, Any]:
    binaries = discover_php_executables()
    return {
        "schema_version": 1,
        "feature": "Local Host PHP Inventory Scan",
        "mode": "local-host-php-inventory-scan",
        "search_scope": "PATH",
        "executables_found": len(binaries),
        "executables": [str(binary) for binary in binaries],
        "issues": [],
        "limitations": [
            "Only PHP executables discoverable by known names in PATH are included.",
            "Discovered executables are not run; their versions and modules are not verified.",
            "This does not search the whole filesystem or establish FPM, Apache, or production runtime state.",
        ],
    }
