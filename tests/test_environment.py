from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from patrick.cli import main
from patrick.environment import (
    discover_php_executables,
    inspect_php_runtime,
)
from patrick.web_runtime import inspect_apache, inspect_php_fpm


class EnvironmentScanTests(unittest.TestCase):
    def setUp(self) -> None:
        cache = tempfile.TemporaryDirectory()
        self.addCleanup(cache.cleanup)
        cache_environment = patch.dict(os.environ, {"XDG_CACHE_HOME": cache.name})
        cache_environment.start()
        self.addCleanup(cache_environment.stop)
        lifecycle = patch(
            "patrick.cli.refresh_php_lifecycle",
            return_value=(
                {},
                {
                    "status": "not_required",
                    "source": "endoflife.date PHP lifecycle data",
                    "issues": [],
                },
            ),
        )
        lifecycle.start()
        self.addCleanup(lifecycle.stop)

    def test_inspects_version_modules_and_ini_without_shell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "php"
            binary.touch()
            binary.chmod(0o755)
            responses = {
                ("--version",): "PHP 8.4.27 (cli) (built: today)\n",
                ("-m",): "[PHP Modules]\njson\nmbstring\n\n[Zend Modules]\nopcache\n",
                ("--ini",): (
                    "Loaded Configuration File: /etc/php.ini\n"
                    "Scan for additional .ini files in: /etc/php/conf.d\n"
                ),
            }

            def run(args, **kwargs):
                self.assertEqual(args[0], str(binary.resolve()))
                self.assertNotIn("shell", kwargs)
                return subprocess.CompletedProcess(
                    args, 0, stdout=responses[tuple(args[1:])], stderr=""
                )

            with patch("patrick.environment.subprocess.run", side_effect=run):
                result = inspect_php_runtime(binary)

        self.assertEqual(result["version"], "8.4.27")
        self.assertEqual(result["modules"], ["json", "mbstring", "opcache"])
        self.assertEqual(result["loaded_configuration"], "/etc/php.ini")
        self.assertEqual(result["sapi"], "CLI executable")

    def test_finds_known_php_names_in_path_without_running_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            php = Path(directory) / "php"
            php.touch()
            php.chmod(0o755)
            with patch.dict(os.environ, {"PATH": directory}):
                found = discover_php_executables()

        self.assertEqual(found, [php.resolve()])

    def test_inspects_php_fpm_version_and_modules_without_shell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "php-fpm"
            binary.touch()
            binary.chmod(0o755)
            responses = {
                ("-v",): "PHP 8.5.12 (fpm-fcgi) (built: today)\n",
                ("-m",): "[PHP Modules]\njson\npdo_mysql\n",
            }

            def run(args, **kwargs):
                self.assertEqual(args[0], str(binary.resolve()))
                self.assertNotIn("shell", kwargs)
                return subprocess.CompletedProcess(
                    args, 0, stdout=responses[tuple(args[1:])], stderr=""
                )

            with patch("patrick.web_runtime.subprocess.run", side_effect=run):
                result = inspect_php_fpm(binary)

        self.assertEqual(result["version"], "8.5.12")
        self.assertEqual(result["modules"], ["json", "pdo_mysql"])
        self.assertEqual(result["sapi"], "PHP-FPM executable")

    def test_inspects_apache_version_and_modules_without_starting_server(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "httpd"
            binary.touch()
            binary.chmod(0o755)
            responses = {
                ("-v",): "Server version: Apache/2.4.62 (Unix)\n",
                ("-M",): (
                    "Loaded Modules:\n"
                    " core_module (static)\n"
                    " proxy_module (shared)\n"
                    " proxy_fcgi_module (shared)\n"
                ),
            }

            def run(args, **kwargs):
                self.assertEqual(args[0], str(binary.resolve()))
                self.assertNotIn("shell", kwargs)
                return subprocess.CompletedProcess(
                    args, 0, stdout=responses[tuple(args[1:])], stderr=""
                )

            with patch("patrick.web_runtime.subprocess.run", side_effect=run):
                result = inspect_apache(binary)

        self.assertEqual(result["version"], "2.4.62")
        self.assertEqual(
            result["modules"],
            ["core_module", "proxy_fcgi_module", "proxy_module"],
        )

    @patch("patrick.cli.refresh_php_releases")
    @patch("patrick.cli.scan_local_environment")
    def test_environment_mode_reports_its_named_feature(
        self, scan_runtime, refresh
    ) -> None:
        scan_runtime.return_value = {
            "schema_version": 1,
            "feature": "Local PHP Runtime Scan",
            "mode": "local-php-runtime-scan",
            "runtime": {
                "binary": "/tmp/php",
                "version": "8.5.11",
                "modules": ["json"],
                "limitations": [],
            },
            "issues": [],
        }
        output = StringIO()
        with redirect_stdout(output):
            exit_code = main(
                ["--mode", "environment", "--php-bin", "/tmp/php", "--offline", "--format", "json"]
            )

        report = json.loads(output.getvalue())
        self.assertEqual(report["feature"], "Local PHP Runtime Scan")
        self.assertEqual(report["runtime"]["results"][0]["evidence"]["authority"],
                         "local-runtime-observation")
        self.assertEqual(exit_code, 1)
        refresh.assert_not_called()

    @patch("patrick.cli.scan_local_environment")
    def test_environment_text_marks_unmatched_extensions_unassessed(
        self, scan_runtime
    ) -> None:
        scan_runtime.return_value = {
            "schema_version": 1,
            "feature": "Local PHP Runtime Scan",
            "mode": "local-php-runtime-scan",
            "runtime": {
                "binary": "/tmp/php",
                "version": "8.5.12",
                "modules": ["json"],
                "limitations": [],
            },
            "issues": [],
        }
        output = StringIO()

        with redirect_stdout(output):
            main(
                [
                    "--mode",
                    "environment",
                    "--php-bin",
                    "/tmp/php",
                    "--offline",
                ]
            )

        self.assertIn("Loaded extension advisory coverage: partial.", output.getvalue())
        self.assertIn(
            "Loaded extensions without matching advisory definitions "
            "(not assessed): json",
            output.getvalue(),
        )

    @patch("patrick.cli.refresh_php_releases")
    @patch("patrick.cli.scan_local_host")
    def test_device_mode_is_a_path_scoped_host_inventory(
        self, scan_host, refresh
    ) -> None:
        scan_host.return_value = {
            "schema_version": 1,
            "feature": "Local Host PHP Inventory Scan",
            "mode": "local-host-php-inventory-scan",
            "search_scope": "PATH",
            "executables_found": 1,
            "executables": ["/usr/local/bin/php"],
            "issues": [],
            "limitations": [],
        }
        output = StringIO()
        with redirect_stdout(output):
            exit_code = main(["--mode", "device", "--format", "json"])

        report = json.loads(output.getvalue())
        self.assertEqual(report["feature"], "Local Host PHP Inventory Scan")
        self.assertEqual(report["search_scope"], "PATH")
        self.assertEqual(report["executables"], ["/usr/local/bin/php"])
        self.assertEqual(exit_code, 0)
        refresh.assert_not_called()

    def test_web_runtime_requires_an_explicit_binary(self) -> None:
        output = StringIO()
        errors = StringIO()
        with redirect_stdout(output), patch("sys.stderr", errors):
            exit_code = main(["--mode", "web-runtime"])

        self.assertEqual(exit_code, 2)
        self.assertIn("requires --php-fpm-bin", errors.getvalue())

    @patch("patrick.cli._runtime_report")
    @patch("patrick.cli._get_release_data")
    @patch("patrick.cli.scan_local_web_runtime")
    def test_web_runtime_assesses_fpm_and_reports_apache_inventory_only(
        self, scan_web, release_data, runtime_report
    ) -> None:
        scan_web.return_value = {
            "schema_version": 1,
            "feature": "Local PHP Web Runtime Scan",
            "mode": "local-php-web-runtime-scan",
            "php_fpm": {
                "binary": "/usr/sbin/php-fpm",
                "version": "8.5.12",
                "modules": ["json"],
                "limitations": [],
                "issues": [],
            },
            "apache": {
                "binary": "/usr/sbin/httpd",
                "version": "2.4.62",
                "modules": ["proxy_fcgi_module"],
                "limitations": [],
                "issues": [],
            },
            "issues": [],
            "limitations": [],
        }
        release_data.return_value = (
            {},
            {"status": "updated", "issues": []},
        )
        runtime_report.return_value = {
            "binary": "/usr/sbin/php-fpm",
            "version": "8.5.12",
            "modules": ["json"],
            "results": [],
            "release_update": {"status": "current", "security_release": False},
            "limitations": [],
        }
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "--mode",
                    "web-runtime",
                    "--php-fpm-bin",
                    "/usr/sbin/php-fpm",
                    "--apache-bin",
                    "/usr/sbin/httpd",
                    "--format",
                    "json",
                ]
            )

        report = json.loads(output.getvalue())
        self.assertEqual(report["feature"], "Local PHP Web Runtime Scan")
        self.assertEqual(report["php_fpm"]["version"], "8.5.12")
        self.assertEqual(report["apache"]["modules"], ["proxy_fcgi_module"])
        self.assertIn("no Apache advisory catalog", report["issues"][0])
        self.assertEqual(exit_code, 3)


if __name__ == "__main__":
    unittest.main()
