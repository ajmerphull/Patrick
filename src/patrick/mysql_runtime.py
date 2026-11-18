from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any


_VERSION_RE = re.compile(r"(?<!\d)(\d+\.\d+\.\d+(?:\.\d+)?)(?!\d)")
_SERVER_NAMES = {
    "mysqld",
    "mysqld-debug",
    "mariadbd",
    "mysqld.exe",
    "mysqld-debug.exe",
    "mariadbd.exe",
}
_TIMEOUT_SECONDS = 5


def inspect_mysql_server(binary: Path) -> dict[str, Any]:
    binary = binary.expanduser().resolve()
    if (
        binary.name.lower() not in _SERVER_NAMES
        or not binary.is_file()
        or not os.access(binary, os.X_OK)
    ):
        raise ValueError(
            "MySQL server path must be an executable named mysqld, mysqld-debug, "
            "or mariadbd."
        )
    try:
        result = subprocess.run(
            [str(binary), "--version"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"Could not inspect MySQL server executable {binary}: {exc}") from exc
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or result.stdout.strip()
        raise ValueError(
            f"MySQL server executable {binary} returned {result.returncode}: {diagnostic}"
        )
    output = (result.stdout + "\n" + result.stderr).strip()
    match = _VERSION_RE.search(output)
    if match is None:
        raise ValueError(f"Could not parse server version from {binary} --version.")
    product = "MariaDB" if "mariadb" in output.lower() else "Oracle MySQL"
    return {
        "binary": str(binary),
        "product": product,
        "version": match.group(1),
        "command": ["--version"],
        "limitations": [
            "The selected server executable was inspected but not started or connected to; this may not be the version used by a running service.",
            "Only Oracle MySQL versions are matched to the NVD catalog; MariaDB is a separate product.",
        ],
    }
