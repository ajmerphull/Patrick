from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from patrick.cli import _exit_code, _get_release_data, main
from patrick.scanner import (
    Declaration,
    Rule,
    _assess_php_lifecycle,
    assess_runtime_version,
    load_rules,
    scan,
)


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
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
        self.root = Path(self.temp.name)
        self.rules = load_rules()

    def write(self, name: str, content: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_detects_old_and_fixed_docker_image_tags(self) -> None:
        self.write("Dockerfile", "FROM php:8.5.11-fpm-alpine\nFROM php:8.5.12-cli\n")

        report = scan(self.root, self.rules)

        self.assertEqual(report["declarations_found"], 2)
        statuses = [result["status"] for result in report["results"]]
        self.assertEqual(statuses.count("potentially_affected"), 2)
        self.assertEqual(statuses.count("fixed"), 2)

    def test_non_exact_or_unlisted_version_is_unknown(self) -> None:
        self.write(".php-version", "8.5\n")

        report = scan(self.root, self.rules)

        self.assertEqual(report["declarations_found"], 1)
        self.assertEqual({row["status"] for row in report["results"]}, {"unknown"})

    def test_reads_compose_and_composer_platform_as_declarations(self) -> None:
        self.write("compose.yaml", "services:\n  web:\n    image: php:8.4.26-fpm\n")
        self.write(
            "composer.json",
            json.dumps({"config": {"platform": {"php": "8.4.27"}}}),
        )

        report = scan(self.root, self.rules)

        self.assertEqual(report["declarations_found"], 2)
        self.assertEqual(
            {row["status"] for row in report["results"]},
            {"potentially_affected", "fixed"},
        )
        self.assertEqual(
            {row["evidence"]["authority"] for row in report["results"]},
            {"repository-declaration"},
        )

    def test_reports_official_latest_release_separately_from_cve_status(self) -> None:
        self.write(".php-version", "8.5.11")
        latest = {
            "8.5": {
                "version": "8.5.12",
                "date": "21 Oct 2026",
                "supported": True,
                "security_release": True,
                "source_url": "https://www.php.net/releases/index.php?json&version=8.5",
                "checked_at": "2026-11-16T00:00:00+00:00",
            }
        }

        report = scan(self.root, self.rules, latest)

        self.assertEqual(report["release_updates"][0]["status"], "update_available")
        self.assertTrue(report["release_updates"][0]["security_release"])
        self.assertEqual(report["results"][0]["status"], "potentially_affected")

    def test_assesses_active_security_maintenance_eol_and_unknown_branches(self) -> None:
        class FrozenDateTime:
            @staticmethod
            def now(tz=None):
                return datetime(2026, 11, 17, tzinfo=timezone.utc)

            @staticmethod
            def strptime(value, format_string):
                return datetime.strptime(value, format_string)

        with patch("patrick.scanner.datetime", FrozenDateTime):
            active = _assess_php_lifecycle(
                Declaration("a.php", 1, "test", "8.5.12", (8, 5, 12), None),
                {"support_date": "2027-12-31", "eol_date": "2029-12-31"},
            )
            maintenance = _assess_php_lifecycle(
                Declaration("a.php", 1, "test", "8.2.35", (8, 2, 35), None),
                {"support_date": "2024-12-31", "eol_date": "2026-12-31"},
            )
            eol = _assess_php_lifecycle(
                Declaration("a.php", 1, "test", "8.1.34", (8, 1, 34), None),
                {"support_date": "2023-11-25", "eol_date": "2025-12-31"},
            )
            unknown = _assess_php_lifecycle(
                Declaration("a.php", 1, "test", "9.0.1", (9, 0, 1), None), None
            )
            eol_without_support = _assess_php_lifecycle(
                Declaration("a.php", 1, "test", "5.6.40", (5, 6, 40), None),
                {"support_date": None, "eol_date": "2018-12-31"},
            )
            unknown_without_eol = _assess_php_lifecycle(
                Declaration("a.php", 1, "test", "8.2.35", (8, 2, 35), None),
                {"support_date": "2024-12-31", "eol_date": None},
            )

        self.assertEqual(active["status"], "active_support")
        self.assertEqual(maintenance["status"], "security_maintenance")
        self.assertEqual(eol["status"], "end_of_life")
        self.assertEqual(unknown["status"], "unknown")
        self.assertEqual(eol_without_support["status"], "end_of_life")
        self.assertEqual(unknown_without_eol["status"], "unknown")

    def test_project_scan_reports_lifecycle_separately_and_eol_affects_exit(self) -> None:
        class FrozenDateTime:
            @staticmethod
            def now(tz=None):
                return datetime(2026, 11, 17, tzinfo=timezone.utc)

            @staticmethod
            def strptime(value, format_string):
                return datetime.strptime(value, format_string)

        with patch("patrick.scanner.datetime", FrozenDateTime):
            self.write(".php-version", "8.1.34")
            report = scan(
                self.root,
                self.rules,
                {
                    "8.1": {
                        "lifecycle": {
                            "cycle": "8.1",
                            "support_date": "2023-11-25",
                            "eol_date": "2025-12-31",
                            "latest_version": "8.1.34",
                            "latest_release_date": "2025-12-18",
                            "lts": False,
                            "source_url": "https://endoflife.date/api/php.json",
                            "checked_at": "2026-11-17T00:00:00+00:00",
                        }
                    }
                },
            )

        self.assertEqual(
            report["release_updates"][0]["lifecycle"]["status"], "end_of_life"
        )
        self.assertEqual(_exit_code(report), 1)

    @patch("patrick.cli.refresh_php_lifecycle")
    @patch("patrick.cli.refresh_php_releases")
    def test_lifecycle_data_is_merged_even_when_phpnet_check_is_offline(
        self, release_fetch, lifecycle_fetch
    ) -> None:
        lifecycle_fetch.return_value = (
            {
                "8.5": {
                    "cycle": "8.5",
                    "support_date": "2027-12-31",
                    "eol_date": "2029-12-31",
                    "latest_version": "8.5.12",
                    "latest_release_date": "2026-10-21",
                    "lts": False,
                    "source_url": "https://endoflife.date/api/php.json",
                    "checked_at": "2026-11-17T00:00:00+00:00",
                }
            },
            {
                "status": "cached",
                "source": "endoflife.date PHP lifecycle data",
                "source_url": "https://endoflife.date/api/php.json",
                "issues": [],
            },
        )
        rules = [
            Rule(
                "TEST",
                "Test",
                "high",
                "Test",
                "php-core",
                (),
                {"8.5": (8, 5, 12)},
            )
        ]

        releases, check = _get_release_data(rules, offline=True)

        release_fetch.assert_not_called()
        lifecycle_fetch.assert_called_once_with({"8.5"}, offline=True)
        self.assertEqual(releases["8.5"]["lifecycle"]["eol_date"], "2029-12-31")
        self.assertEqual(check["status"], "skipped")
        self.assertEqual(check["lifecycle_check"]["status"], "cached")

    def test_ignores_vendor_and_non_php_images(self) -> None:
        self.write("vendor/example/Dockerfile", "FROM php:8.2.34-fpm\n")
        self.write("Dockerfile", "FROM nginx:1.27\n")

        report = scan(self.root, self.rules)

        self.assertEqual(report["declarations_found"], 0)
        self.assertEqual(report["results"], [])

    def test_non_official_php_image_is_unknown(self) -> None:
        self.write("Dockerfile", "FROM registry.example/team/php:8.5.12\n")

        report = scan(self.root, self.rules)

        self.assertEqual(report["declarations_found"], 1)
        self.assertEqual({row["status"] for row in report["results"]}, {"unknown"})

    def test_variable_image_reference_is_not_treated_as_clean(self) -> None:
        self.write("Dockerfile", "ARG PHP_IMAGE\nFROM ${PHP_IMAGE}\n")

        report = scan(self.root, self.rules)

        self.assertEqual(report["declarations_found"], 1)
        self.assertEqual({row["status"] for row in report["results"]}, {"unknown"})

    def test_custom_rule_catalog_is_supported(self) -> None:
        catalog = self.root / "custom.json"
        catalog.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "rules": [
                        {
                            "id": "TEST-1",
                            "title": "Test rule",
                            "severity": "high",
                            "summary": "A test advisory",
                            "references": [],
                            "fixed_versions": {"8.5": "8.5.20"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.write(".php-version", "8.5.12")

        report = scan(self.root, load_rules(catalog))

        self.assertEqual(report["results"][0]["rule_id"], "TEST-1")
        self.assertEqual(report["results"][0]["status"], "potentially_affected")

    def test_project_declarations_do_not_assess_extension_advisories(self) -> None:
        extension_rule = Rule(
            id="CVE-2026-12345",
            title="Extension advisory",
            severity="high",
            summary="An extension advisory.",
            component="php-extension",
            references=(),
            fixed_versions={"8.5": (8, 5, 12)},
            package_name="openssl",
        )
        self.write(".php-version", "8.5.11")

        report = scan(self.root, [extension_rule])

        self.assertEqual(report["declarations_found"], 1)
        self.assertEqual(report["results"], [])

    def test_runtime_extension_advisory_matches_loaded_module(self) -> None:
        extension_rule = Rule(
            id="CVE-2026-12345",
            title="OpenSSL extension advisory",
            severity="high",
            summary="An extension advisory.",
            component="php-extension",
            references=(),
            fixed_versions={"8.5": (8, 5, 12)},
            package_name="openssl",
        )
        core_rule = Rule(
            id="CVE-2026-54321",
            title="PHP core advisory",
            severity="high",
            summary="A core advisory.",
            component="php-core",
            references=(),
            fixed_versions={"8.5": (8, 5, 12)},
        )

        report = assess_runtime_version(
            "8.5.11",
            "/usr/sbin/php-fpm",
            [core_rule, extension_rule],
            {},
            ["OpenSSL", "json"],
        )

        self.assertEqual([row["rule_id"] for row in report["results"]], ["CVE-2026-54321"])
        extension_result = report["extension_assessment"]["results"][0]
        self.assertEqual(extension_result["rule_id"], "CVE-2026-12345")
        self.assertEqual(extension_result["status"], "potentially_affected")
        self.assertEqual(
            extension_result["evidence"]["extension_module"], "OpenSSL"
        )
        self.assertIsNone(extension_result["evidence"]["extension_version"])
        self.assertEqual(
            report["extension_assessment"]["modules_without_advisories"], ["json"]
        )
        self.assertEqual(report["extension_assessment"]["status"], "partial")

    @patch(
        "patrick.cli.refresh_php_releases",
        return_value=(
            {},
            {"status": "updated", "source": "PHP.net", "issues": []},
        ),
    )
    def test_cli_exit_codes_distinguish_affected_from_empty_scope(self, _refresh) -> None:
        output = StringIO()
        self.write(".php-version", "8.5.11")
        with redirect_stdout(output):
            affected_code = main([str(self.root)])
        self.assertEqual(affected_code, 1)
        self.assertIn("POTENTIALLY_AFFECTED", output.getvalue())

        empty_root = self.root / "empty"
        empty_root.mkdir()
        with redirect_stdout(StringIO()):
            empty_code = main([str(empty_root), "--format", "json"])
        self.assertEqual(empty_code, 3)

    @patch("patrick.cli.refresh_php_releases")
    def test_offline_mode_skips_release_fetch_and_reports_unknown_status(
        self, refresh
    ) -> None:
        self.write(".php-version", "8.5.11")
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main([str(self.root), "--offline", "--format", "json"])

        refresh.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(report["update_check"]["status"], "skipped")
        self.assertEqual(report["release_updates"][0]["status"], "unknown")

    @patch("patrick.cli.refresh_php_releases")
    def test_invalid_target_fails_before_network_update_check(self, refresh) -> None:
        with redirect_stdout(StringIO()):
            exit_code = main([str(self.root / "missing")])

        refresh.assert_not_called()
        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
