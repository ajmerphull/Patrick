from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from patrick.definition_list import default_php_version
from patrick.web_ui import (
    _JOB_DEFINITIONS,
    _job_argv,
    _network_purposes,
    create_app,
)


_LOCAL_HEADERS = {"Origin": "http://127.0.0.1"}


def _client(app) -> TestClient:
    return TestClient(
        app,
        base_url="http://127.0.0.1",
        client=("127.0.0.1", 50000),
    )


def _finish_job(client: TestClient) -> dict:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        job = client.get("/api/jobs/current").json()["job"]
        if job and job["status"] not in {"queued", "running"}:
            return job
        time.sleep(0.01)
    raise AssertionError("Patrick job did not finish within three seconds.")


class WebUiTests(unittest.TestCase):
    def test_job_menu_exposes_all_cli_jobs_and_accessible_page(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _client(create_app(Path(directory) / "consent.json")) as client:
                page = client.get("/")
                stylesheet = client.get("/assets/style.css")
                script = client.get("/assets/app.js")
                jobs = client.get("/api/jobs").json()["jobs"]

        self.assertEqual(page.status_code, 200)
        self.assertIn("aria-live", page.text)
        self.assertIn('/assets/style.css', page.text)
        self.assertIn('/assets/app.js', page.text)
        self.assertEqual(stylesheet.status_code, 200)
        self.assertEqual(stylesheet.headers["content-type"], "text/css; charset=utf-8")
        self.assertIn("color-scheme:dark", stylesheet.text)
        self.assertEqual(script.status_code, 200)
        self.assertEqual(
            script.headers["content-type"],
            "text/javascript; charset=utf-8",
        )
        self.assertIn("Definition-list coverage:", script.text)
        self.assertIn("php-version-options", script.text)
        self.assertEqual(
            page.headers["content-security-policy"],
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'",
        )
        self.assertEqual(
            {job["id"] for job in jobs},
            {
                "project",
                "source",
                "environment",
                "web-runtime",
                "device",
                "definitions",
                "dependencies",
                "list-definitions",
            },
        )
        self.assertEqual({job["id"] for job in _JOB_DEFINITIONS}, {job["id"] for job in jobs})
        definitions = next(job for job in jobs if job["id"] == "definitions")
        profile_field = next(
            field for field in definitions["fields"] if field["name"] == "php_version"
        )
        self.assertIn("8.5", profile_field["options"])
        self.assertIn(profile_field["default"], profile_field["options"])
        self.assertIn(
            "--php-version",
            _job_argv(
                "definitions",
                {"php_version": "8.2", "allow_network": True},
            ),
        )
        self.assertEqual(
            _job_argv(
                "list-definitions",
                {"php_version": "8.2"},
            ),
            ["--mode", "list-definitions", "--php-version", "8.2"],
        )

    def test_requests_are_loopback_and_same_origin_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _client(create_app(Path(directory) / "consent.json")) as client:
                cross_origin = client.post(
                    "/api/jobs",
                    headers={"Origin": "http://example.test"},
                    json={"job": "device", "inputs": {}},
                )
                missing_origin = client.delete("/api/consent")
                bad_host = client.get("/", headers={"Host": "example.test"})

        self.assertEqual(cross_origin.status_code, 403)
        self.assertEqual(missing_origin.status_code, 403)
        self.assertEqual(bad_host.status_code, 403)

    def test_saved_profile_remains_available_when_no_catalog_rule_matches_it(self) -> None:
        with patch(
            "patrick.definition_list.definition_update_status",
            return_value={"php_version_profile": "8.2"},
        ):
            profile = default_php_version()

        self.assertEqual(profile, "8.2")

    def test_definition_job_rejects_malformed_php_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _client(create_app(Path(directory) / "consent.json")) as client:
                response = client.post(
                    "/api/jobs",
                    headers=_LOCAL_HEADERS,
                    json={
                        "job": "definitions",
                        "inputs": {
                            "php_version": "8.2.1",
                            "allow_network": True,
                        },
                    },
                )

        self.assertEqual(response.status_code, 422)
        self.assertIn("major.minor", response.json()["detail"])

    def test_network_checks_are_opt_in_and_session_consent_is_reused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(Path(directory) / "consent.json")
            with patch("patrick.web_ui.cli_main", return_value=0) as run:
                with _client(app) as client:
                    first = client.post(
                        "/api/jobs",
                        headers=_LOCAL_HEADERS,
                        json={
                            "job": "project",
                            "inputs": {
                                "target": directory,
                                "live_data": True,
                            },
                        },
                    )
                    self.assertEqual(first.status_code, 428)
                    self.assertEqual(
                        first.json()["detail"]["consent_required"],
                        ["release_metadata"],
                    )
                    run.assert_not_called()
                    started = client.post(
                        "/api/jobs",
                        headers=_LOCAL_HEADERS,
                        json={
                            "job": "project",
                            "inputs": {
                                "target": directory,
                                "live_data": True,
                            },
                            "confirmed_purposes": ["release_metadata"],
                            "remember_consent": False,
                        },
                    )
                    self.assertEqual(started.status_code, 202)
                    _finish_job(client)
                    again = client.post(
                        "/api/jobs",
                        headers=_LOCAL_HEADERS,
                        json={
                            "job": "project",
                            "inputs": {
                                "target": directory,
                                "live_data": True,
                            },
                        },
                    )

        self.assertEqual(again.status_code, 202)
        self.assertTrue(any("--offline" not in call.args[0] for call in run.call_args_list))

    def test_always_allow_is_persisted_by_network_purpose_and_can_be_revoked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            consent_path = Path(directory) / "consent.json"
            with patch("patrick.web_ui.cli_main", return_value=0):
                app = create_app(consent_path)
                with _client(app) as client:
                    response = client.post(
                        "/api/jobs",
                        headers=_LOCAL_HEADERS,
                        json={
                            "job": "dependencies",
                            "inputs": {"target": directory, "osv_lookup": True},
                            "confirmed_purposes": ["osv"],
                            "remember_consent": True,
                        },
                    )
                    self.assertEqual(response.status_code, 202)
                    _finish_job(client)
                    persisted = json.loads(consent_path.read_text(encoding="utf-8"))
                    self.assertEqual(persisted["always_allow"], ["osv"])
                    self.assertEqual(consent_path.stat().st_mode & 0o777, 0o600)
                    next_app = create_app(consent_path)
                    with _client(next_app) as next_client:
                        permission = next_client.get("/api/consent").json()
                        revoked = next_client.delete(
                            "/api/consent", headers=_LOCAL_HEADERS
                        )

        self.assertEqual(permission["always_allow"], ["osv"])
        self.assertEqual(revoked.status_code, 200)
        self.assertFalse(consent_path.exists())

    def test_only_one_job_can_run_at_a_time(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        def delayed_job(argv, *, stdout, stderr):
            entered.set()
            release.wait(timeout=2)
            stdout.write("completed")
            return 0

        with tempfile.TemporaryDirectory() as directory:
            with patch("patrick.web_ui.cli_main", side_effect=delayed_job):
                with _client(
                    create_app(Path(directory) / "consent.json")
                ) as client:
                    started = client.post(
                        "/api/jobs",
                        headers=_LOCAL_HEADERS,
                        json={"job": "device", "inputs": {}},
                    )
                    self.assertEqual(started.status_code, 202)
                    self.assertTrue(entered.wait(timeout=1))
                    conflict = client.post(
                        "/api/jobs",
                        headers=_LOCAL_HEADERS,
                        json={"job": "device", "inputs": {}},
                    )
                    release.set()
                    finished = _finish_job(client)

        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(finished["status"], "success")
        self.assertEqual(finished["output"], "completed")

    def test_cli_arguments_keep_network_and_optional_switches_off_by_default(self) -> None:
        project = _job_argv("project", {"target": "/tmp/project"})
        source = _job_argv("source", {"target": "/tmp/project"})
        dependencies = _job_argv(
            "dependencies", {"target": "/tmp/project", "osv_lookup": False}
        )

        self.assertIn("--offline", project)
        self.assertIn("--offline", source)
        self.assertIn("--offline", dependencies)
        self.assertNotIn("--skip-environment-check", source)
        self.assertNotIn(
            "--offline",
            _job_argv(
                "dependencies",
                {"target": "/tmp/project", "osv_lookup": True},
            ),
        )

    def test_conditional_fields_are_attached_to_the_correct_jobs(self) -> None:
        jobs = {job["id"]: job for job in _JOB_DEFINITIONS}
        fields = {
            job_id: {field["name"]: field for field in job["fields"]}
            for job_id, job in jobs.items()
        }

        self.assertEqual(fields["source"]["php_bin"]["hide_if"], "skip_environment_check")
        self.assertNotIn("show_if", fields["environment"]["live_data"])
        self.assertEqual(fields["web-runtime"]["live_data"]["show_if"], "php_fpm_bin")

    def test_skipping_source_preflight_rejects_a_php_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with _client(create_app(Path(directory) / "consent.json")) as client:
                response = client.post(
                    "/api/jobs",
                    headers=_LOCAL_HEADERS,
                    json={
                        "job": "source",
                        "inputs": {
                            "target": directory,
                            "php_bin": "/usr/bin/php",
                            "skip_environment_check": True,
                        },
                    },
                )

        self.assertEqual(response.status_code, 422)
        self.assertIn("PHP executable is not used", response.json()["detail"])

    def test_apache_only_web_runtime_stays_offline_even_for_direct_api_input(self) -> None:
        inputs = {"apache_bin": "/usr/sbin/httpd", "live_data": True}

        self.assertEqual(_network_purposes("web-runtime", inputs), set())
        self.assertIn("--offline", _job_argv("web-runtime", inputs))

    def test_web_runtime_live_data_requires_php_fpm(self) -> None:
        php_fpm = {"php_fpm_bin": "/usr/sbin/php-fpm", "live_data": True}
        apache_only = {"apache_bin": "/usr/sbin/httpd", "live_data": True}

        self.assertEqual(_network_purposes("web-runtime", php_fpm), {"release_metadata"})
        self.assertNotIn("--offline", _job_argv("web-runtime", php_fpm))
        self.assertIn("--offline", _job_argv("web-runtime", apache_only))


if __name__ == "__main__":
    unittest.main()
