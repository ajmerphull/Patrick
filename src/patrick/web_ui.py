from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import tempfile
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .cli import main as cli_main
from .definition_list import available_php_versions, default_php_version
from .php_version_profile import normalize_php_version_profile


_PURPOSES = {
    "release_metadata": (
        "PHP.net release metadata and endoflife.date lifecycle data. "
        "Only PHP version and branch information is requested."
    ),
    "osv": (
        "OSV dependency advisories. Exact Composer package names and locked "
        "versions are sent; project paths, source, and lock-file contents are not."
    ),
    "definition_refresh": (
        "NVD PHP/MySQL vulnerability definitions and linked PHP-src GitHub "
        "advisories. No project source or project path is sent."
    ),
}
_MAX_JOB_OUTPUT_CHARS = 1_000_000
_WEB_DIRECTORY = Path(__file__).with_name("web")

_JOB_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "id": "project",
        "name": "Project Version Declaration Scan",
        "description": "Check declared PHP versions in a project against local rules and optional live release/lifecycle data.",
        "fields": [
            {"name": "target", "label": "Project directory", "type": "path", "required": True, "placeholder": "/path/to/php-project"},
            {"name": "rules", "label": "Custom PHP rules file (optional)", "type": "path", "placeholder": "/path/to/php-runtime.json"},
            {"name": "live_data", "label": "Allow live PHP release and lifecycle checks for this run", "type": "checkbox", "purpose": "release_metadata"},
        ],
    },
    {
        "id": "source",
        "name": "PHP Source Syntax Scan",
        "description": "Run a PHP runtime preflight, then scan supported PHP files for configured call signatures.",
        "fields": [
            {"name": "target", "label": "Project directory", "type": "path", "required": True, "placeholder": "/path/to/php-project"},
            {"name": "php_bin", "label": "PHP executable (optional; otherwise use PATH)", "type": "path", "placeholder": "/usr/bin/php", "hide_if": "skip_environment_check"},
            {"name": "source_rules", "label": "Custom PHP source rules file (optional)", "type": "path", "placeholder": "/path/to/php-source.json"},
            {"name": "rules", "label": "Custom PHP runtime rules file (optional)", "type": "path", "placeholder": "/path/to/php-runtime.json"},
            {"name": "skip_environment_check", "label": "Skip local PHP environment preflight", "type": "checkbox", "description": "Opt in only if the local PHP environment has already been checked."},
            {"name": "live_data", "label": "Allow live PHP release and lifecycle checks for this run", "type": "checkbox", "purpose": "release_metadata"},
        ],
    },
    {
        "id": "environment",
        "name": "Local PHP Runtime Scan",
        "description": "Inspect one selected PHP executable, its modules and INI paths, and assess its version.",
        "fields": [
            {"name": "php_bin", "label": "PHP executable", "type": "path", "required": True, "placeholder": "/usr/bin/php"},
            {"name": "rules", "label": "Custom PHP rules file (optional)", "type": "path", "placeholder": "/path/to/php-runtime.json"},
            {"name": "live_data", "label": "Allow live PHP release and lifecycle checks for this run", "type": "checkbox", "purpose": "release_metadata"},
        ],
    },
    {
        "id": "web-runtime",
        "name": "Local PHP Web Runtime Scan",
        "description": "Inspect explicitly selected PHP-FPM and/or Apache executables. Apache is inventoried, not CVE-assessed.",
        "fields": [
            {"name": "php_fpm_bin", "label": "PHP-FPM executable (optional)", "type": "path", "placeholder": "/usr/sbin/php-fpm"},
            {"name": "apache_bin", "label": "Apache/httpd executable (optional)", "type": "path", "placeholder": "/usr/sbin/httpd"},
            {"name": "rules", "label": "Custom PHP rules file (optional)", "type": "path", "placeholder": "/path/to/php-runtime.json"},
            {"name": "live_data", "label": "Allow live PHP release and lifecycle checks for this run", "type": "checkbox", "purpose": "release_metadata", "show_if": "php_fpm_bin"},
        ],
    },
    {
        "id": "device",
        "name": "Local Host PHP Inventory Scan",
        "description": "Find known PHP executable names in the local PATH without running them.",
        "fields": [],
    },
    {
        "id": "definitions",
        "name": "PHP Vulnerability Definition Update",
        "description": "Refresh the shared PHP and MySQL catalogs, then set the default PHP-version profile for the definition list.",
        "fields": [
            {"name": "php_version", "label": "PHP version definition profile", "type": "php-version", "required": True, "description": "The list includes supported rules affecting this PHP branch. The shared catalog retains other branches too."},
            {"name": "allow_network", "label": "Allow outbound requests to refresh vulnerability definitions", "type": "checkbox", "required": True, "purpose": "definition_refresh"},
        ],
    },
    {
        "id": "dependencies",
        "name": "MySQL & Third-Party Dependency Scan",
        "description": "Check exact Composer lock versions against OSV and optionally inspect a local MySQL server executable.",
        "fields": [
            {"name": "target", "label": "Project directory", "type": "path", "required": True, "placeholder": "/path/to/php-project"},
            {"name": "mysql_bin", "label": "MySQL server executable (optional; version only)", "type": "path", "placeholder": "/usr/local/mysql/bin/mysqld"},
            {"name": "osv_lookup", "label": "Allow OSV advisory lookup for locked Composer packages", "type": "checkbox", "purpose": "osv", "description": "Sends package names and exact locked versions only."},
        ],
    },
    {
        "id": "list-definitions",
        "name": "Vulnerability Definition List",
        "description": "List local PHP CVE definitions affecting a selected PHP branch, or all branches. No network request.",
        "fields": [
            {"name": "php_version", "label": "PHP version definition profile", "type": "php-version", "required": True, "description": "PHP core is prioritized; extension definitions are best-effort and do not cover every extension."},
            {"name": "rules", "label": "Custom PHP rules file (optional)", "type": "path", "placeholder": "/path/to/php-runtime.json"},
        ],
    },
)
_JOB_BY_ID = {job["id"]: job for job in _JOB_DEFINITIONS}
_JOB_LABEL = {job["id"]: job["name"] for job in _JOB_DEFINITIONS}


class JobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    confirmed_purposes: list[str] | None = None
    remember_consent: bool = False


def _consent_file() -> Path:
    configured = os.environ.get("XDG_CONFIG_HOME")
    root = Path(configured) if configured else Path.home() / ".config"
    return root / "patrick" / "web-ui-consent.json"


def _load_saved_consents(path: Path) -> set[str]:
    if not path.exists():
        return set()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Network consent file is not a regular file: {path}")
    try:
        if path.stat().st_size > 16 * 1024:
            raise ValueError("Network consent file exceeds the 16 KiB limit.")
        data: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read network consent file {path}: {exc}") from exc
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != 1
        or not isinstance(data.get("always_allow"), list)
        or any(
            not isinstance(purpose, str) or purpose not in _PURPOSES
            for purpose in data["always_allow"]
        )
    ):
        raise ValueError(f"Network consent file has an invalid schema: {path}")
    return set(data["always_allow"])


def _save_consents(path: Path, purposes: set[str]) -> None:
    directory = path.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink():
        raise OSError(f"Network consent directory cannot be a symbolic link: {directory}")
    try:
        directory.chmod(0o700)
    except OSError as exc:
        raise OSError(f"Could not secure network consent directory {directory}: {exc}") from exc
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=directory, delete=False
        ) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            json.dump(
                {"schema_version": 1, "always_allow": sorted(purposes)},
                stream,
                indent=2,
            )
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _validate_job_inputs(job: str, inputs: Any) -> dict[str, str | bool]:
    definition = _JOB_BY_ID.get(job)
    if definition is None:
        raise HTTPException(status_code=422, detail="Unknown Patrick job.")
    if not isinstance(inputs, dict):
        raise HTTPException(status_code=422, detail="Job inputs must be an object.")
    field_map = {field["name"]: field for field in definition["fields"]}
    unknown = set(inputs) - set(field_map)
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported input field(s): {', '.join(sorted(unknown))}.",
        )
    normalized: dict[str, str | bool] = {}
    for name, field in field_map.items():
        value = inputs.get(name)
        if field["type"] == "checkbox":
            if value is None:
                value = False
            if not isinstance(value, bool):
                raise HTTPException(
                    status_code=422,
                    detail=f"{field['label']} must be a boolean.",
                )
            normalized[name] = value
            if field.get("required") and not value:
                raise HTTPException(
                    status_code=422,
                    detail=f"Select the opt-in checkbox: {field['label']}.",
                )
            continue
        if field["type"] == "php-version":
            if not isinstance(value, str):
                raise HTTPException(
                    status_code=422,
                    detail="PHP version profile must be a major.minor branch such as 8.2, or 'all'.",
                )
            try:
                normalize_php_version_profile(value)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            normalized[name] = value
            continue
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise HTTPException(
                status_code=422, detail=f"{field['label']} must be a path string."
            )
        value = value.strip()
        if field.get("required") and not value:
            raise HTTPException(
                status_code=422, detail=f"{field['label']} is required."
            )
        if value:
            normalized[name] = value

    if job == "web-runtime" and not (
        normalized.get("php_fpm_bin") or normalized.get("apache_bin")
    ):
        raise HTTPException(
            status_code=422,
            detail="Select a PHP-FPM executable, an Apache executable, or both.",
        )
    if job == "source" and normalized.get("skip_environment_check") and normalized.get("php_bin"):
        raise HTTPException(
            status_code=422,
            detail="PHP executable is not used when the environment preflight is skipped.",
        )
    return normalized


def _network_purposes(job: str, inputs: dict[str, str | bool]) -> set[str]:
    if job == "definitions":
        return {"definition_refresh"}
    if job in {"project", "source", "environment"}:
        return {"release_metadata"} if inputs.get("live_data") else set()
    if job == "web-runtime":
        return (
            {"release_metadata"}
            if inputs.get("php_fpm_bin") and inputs.get("live_data")
            else set()
        )
    if job == "dependencies" and inputs.get("osv_lookup"):
        return {"osv"}
    return set()


def _job_argv(job: str, inputs: dict[str, str | bool]) -> list[str]:
    argv = ["--mode", job]
    if job in {"project", "source", "dependencies"}:
        argv.append(str(inputs["target"]))
    if job == "project":
        if inputs.get("rules"):
            argv.extend(["--rules", str(inputs["rules"])])
        if not inputs.get("live_data"):
            argv.append("--offline")
    elif job == "source":
        for key, option in (
            ("php_bin", "--php-bin"),
            ("source_rules", "--source-rules"),
            ("rules", "--rules"),
        ):
            if inputs.get(key):
                argv.extend([option, str(inputs[key])])
        if inputs.get("skip_environment_check"):
            argv.append("--skip-environment-check")
        if not inputs.get("live_data"):
            argv.append("--offline")
    elif job == "environment":
        argv.extend(["--php-bin", str(inputs["php_bin"])])
        if inputs.get("rules"):
            argv.extend(["--rules", str(inputs["rules"])])
        if not inputs.get("live_data"):
            argv.append("--offline")
    elif job == "web-runtime":
        if inputs.get("php_fpm_bin"):
            argv.extend(["--php-fpm-bin", str(inputs["php_fpm_bin"])])
        if inputs.get("apache_bin"):
            argv.extend(["--apache-bin", str(inputs["apache_bin"])])
        if inputs.get("rules"):
            argv.extend(["--rules", str(inputs["rules"])])
        if not (inputs.get("php_fpm_bin") and inputs.get("live_data")):
            argv.append("--offline")
    elif job == "dependencies":
        if inputs.get("mysql_bin"):
            argv.extend(["--mysql-bin", str(inputs["mysql_bin"])])
        if not inputs.get("osv_lookup"):
            argv.append("--offline")
    elif job == "definitions":
        argv.extend(["--php-version", str(inputs["php_version"])])
    elif job == "list-definitions":
        argv.extend(["--php-version", str(inputs["php_version"])])
        if inputs.get("rules"):
            argv.extend(["--rules", str(inputs["rules"])])
    return argv


def _check_local_request(request: Request) -> None:
    client_host = request.client.host if request.client else ""
    try:
        is_loopback = ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        raise HTTPException(status_code=403, detail="Patrick Web UI accepts loopback clients only.")

    host_header = request.headers.get("host", "")
    try:
        host = urlsplit(f"//{host_header}")
        if host.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError
        host_port = host.port or 80
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Invalid or non-loopback Host header.") from exc

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin_value = request.headers.get("origin")
        if not origin_value:
            raise HTTPException(status_code=403, detail="A same-origin request is required.")
        try:
            origin = urlsplit(origin_value)
            if (
                origin.scheme != "http"
                or origin.hostname not in {"127.0.0.1", "localhost", "::1"}
                or (origin.port or 80) != host_port
                or origin.hostname != host.hostname
            ):
                raise ValueError
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="Cross-origin requests are not allowed.") from exc


def _run_cli_job(app: FastAPI, job_record: dict[str, Any], argv: list[str]) -> None:
    with app.state.lock:
        job_record["status"] = "running"
        job_record["phase"] = f"Running {_JOB_LABEL[job_record['job']]}."
        job_record["updated_at"] = datetime.now(timezone.utc).isoformat()
    stdout = StringIO()
    stderr = StringIO()
    exit_code = cli_main(argv, stdout=stdout, stderr=stderr)
    output = stdout.getvalue()
    error_output = stderr.getvalue()
    if error_output:
        output = f"{output.rstrip()}\n{error_output.rstrip()}".strip()
    if len(output) > _MAX_JOB_OUTPUT_CHARS:
        output = (
            output[:_MAX_JOB_OUTPUT_CHARS]
            + "\n[Patrick Web UI truncated output after 1,000,000 characters.]"
        )
    result_status = {
        0: "success",
        1: "findings",
        2: "error",
        3: "incomplete",
    }.get(exit_code, "error")
    with app.state.lock:
        job_record.update(
            {
                "status": result_status,
                "phase": "Finished.",
                "exit_code": exit_code,
                "output": output,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )


def _job_done(app: FastAPI, job_record: dict[str, Any], future: Future[None]) -> None:
    error = future.exception()
    if error is None:
        return
    with app.state.lock:
        job_record.update(
            {
                "status": "error",
                "phase": "Job failed.",
                "error": f"{type(error).__name__}: {error}",
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )


def create_app(consent_path: Path | None = None) -> FastAPI:
    application = FastAPI(
        title="Patrick Web UI",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.lock = threading.Lock()
    application.state.executor = ThreadPoolExecutor(
        max_workers=1, thread_name_prefix="patrick-web-job"
    )
    application.state.current_job = None
    application.state.future = None
    application.state.consent_path = consent_path or _consent_file()
    application.state.persistent_consents = None
    application.state.session_consents = set()
    application.mount(
        "/assets",
        StaticFiles(directory=_WEB_DIRECTORY),
        name="web-assets",
    )

    @application.middleware("http")
    async def local_only(request: Request, call_next):
        try:
            _check_local_request(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def saved_consents() -> set[str]:
        if application.state.persistent_consents is None:
            try:
                application.state.persistent_consents = _load_saved_consents(
                    application.state.consent_path
                )
            except ValueError as exc:
                raise HTTPException(status_code=500, detail=str(exc)) from exc
        return application.state.persistent_consents

    @application.get("/")
    async def index() -> FileResponse:
        return FileResponse(_WEB_DIRECTORY / "index.html")

    @application.get("/api/jobs")
    async def jobs() -> dict[str, Any]:
        branches = available_php_versions()
        default_branch = default_php_version()
        job_rows = []
        for job in _JOB_DEFINITIONS:
            row = {**job, "fields": [dict(field) for field in job["fields"]]}
            for field in row["fields"]:
                if field["type"] == "php-version":
                    field["options"] = ["all", *branches]
                    field["default"] = default_branch
            job_rows.append(row)
        return {"jobs": job_rows, "network_purposes": _PURPOSES}

    @application.post("/api/jobs", status_code=202)
    async def start_job(payload: JobRequest, request: Request) -> Any:
        if payload.job not in _JOB_BY_ID:
            raise HTTPException(status_code=422, detail="Unknown Patrick job.")
        normalized = _validate_job_inputs(payload.job, payload.inputs)
        required_purposes = _network_purposes(payload.job, normalized)
        available_consents = saved_consents() | application.state.session_consents
        missing_purposes = required_purposes - available_consents
        if missing_purposes:
            if payload.confirmed_purposes is None:
                return JSONResponse(
                    status_code=428,
                    content={
                        "detail": {
                            "consent_required": sorted(missing_purposes),
                            "descriptions": {
                                purpose: _PURPOSES[purpose]
                                for purpose in sorted(missing_purposes)
                            },
                        }
                    },
                )
            confirmed = set(payload.confirmed_purposes)
            if (
                len(confirmed) != len(payload.confirmed_purposes)
                or confirmed != missing_purposes
            ):
                raise HTTPException(
                    status_code=422,
                    detail="Confirm exactly the network purposes requested for this job.",
                )
            if payload.remember_consent:
                persisted = available_consents | confirmed
                try:
                    _save_consents(application.state.consent_path, persisted)
                except OSError as exc:
                    raise HTTPException(
                        status_code=500,
                        detail=f"Could not save always-allow consent: {exc}",
                    ) from exc
                application.state.persistent_consents = persisted
            else:
                application.state.session_consents.update(confirmed)
        argv = _job_argv(payload.job, normalized)
        with application.state.lock:
            current = application.state.current_job
            if current and current["status"] in {"queued", "running"}:
                raise HTTPException(
                    status_code=409, detail="A Patrick job is already running."
                )
            now = datetime.now(timezone.utc).isoformat()
            job_record = {
                "id": str(uuid.uuid4()),
                "job": payload.job,
                "label": _JOB_LABEL[payload.job],
                "status": "queued",
                "phase": "Queued.",
                "created_at": now,
                "updated_at": now,
                "output": "",
            }
            application.state.current_job = job_record
            future: Future[None] = application.state.executor.submit(
                _run_cli_job, application, job_record, argv
            )
            future.add_done_callback(
                lambda completed: _job_done(application, job_record, completed)
            )
            application.state.future = future
        return {"job_id": job_record["id"], "status": job_record["status"]}

    @application.get("/api/jobs/current")
    async def current_job() -> dict[str, Any]:
        with application.state.lock:
            current = application.state.current_job
            return {"job": dict(current) if current else None}

    @application.get("/api/consent")
    async def consent_status() -> dict[str, Any]:
        persistent = saved_consents()
        return {
            "always_allow": sorted(persistent),
            "this_session": sorted(application.state.session_consents),
            "purposes": _PURPOSES,
        }

    @application.delete("/api/consent")
    async def revoke_consent() -> dict[str, Any]:
        path: Path = application.state.consent_path
        if path.is_symlink():
            raise HTTPException(
                status_code=500,
                detail=f"Refusing to remove symbolic-link consent file: {path}",
            )
        try:
            if path.exists():
                path.unlink()
        except OSError as exc:
            raise HTTPException(
                status_code=500, detail=f"Could not revoke saved consent: {exc}"
            ) from exc
        application.state.persistent_consents = set()
        application.state.session_consents.clear()
        return {"always_allow": [], "this_session": []}

    return application




app = create_app()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="patrick-web",
        description="Start Patrick's local-only web interface on 127.0.0.1.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="loopback port (default: 8000)",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535.")
    uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
