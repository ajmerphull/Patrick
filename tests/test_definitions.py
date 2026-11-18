from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from patrick.cli import main
from patrick.catalog import definition_update_status
from patrick.definitions import (
    parse_github_advisory,
    refresh_php_definitions,
)
from patrick.scanner import load_rules


_CVE_ID = "CVE-2026-12345"
_GHSA_ID = "GHSA-abcd-efgh-ijkl"
_GHSA_URL = (
    "https://github.com/php/php-src/security/advisories/" + _GHSA_ID
)
_FIXED = {"8.5": "8.5.12"}


def _record(fixed_version: str = "8.5.12") -> dict:
    return {
        "id": _CVE_ID,
        "sourceIdentifier": "security@php.net",
        "published": "2026-10-21T14:17:09.357",
        "lastModified": "2026-11-16T16:54:58.603",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "en", "value": "A test PHP vulnerability affects requests."}
        ],
        "affected": [
            {
                "source": "security@php.net",
                "affectedData": [
                    {
                        "vendor": "PHP Group",
                        "product": "PHP",
                        "packageName": "php-src",
                        "versions": [
                            {
                                "version": "8.5.*",
                                "lessThan": fixed_version,
                                "versionType": "semver",
                                "status": "affected",
                            }
                        ],
                    }
                ],
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}
            ]
        },
        "references": [{"url": _GHSA_URL}],
    }


def _source_metadata() -> dict:
    return {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "sha256": "a" * 64,
        "records": 1,
        "checked_at": "2026-11-17T00:00:00+00:00",
    }


def _write_base_catalog(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "rules": [
                    {
                        "id": "TEST-BASE",
                        "title": "Base test rule",
                        "severity": "low",
                        "component": "php-core",
                        "summary": "A base catalog entry.",
                        "references": [],
                        "fixed_versions": {"8.5": "8.5.10"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


class DefinitionUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        cache = tempfile.TemporaryDirectory()
        self.addCleanup(cache.cleanup)
        cache_environment = patch.dict(os.environ, {"XDG_CACHE_HOME": cache.name})
        cache_environment.start()
        self.addCleanup(cache_environment.stop)

    def test_parses_exact_patched_versions_from_github_advisory(self) -> None:
        html = f"""
        <html><body>
          <p>{_GHSA_ID} {_CVE_ID}</p>
          <h2>Affected versions</h2>
          <div class="f4">&lt; 8.5.12</div>
          <h2>Patched versions</h2>
          <div class="f4">8.5.12</div>
        </body></html>
        """

        versions, digest = parse_github_advisory(
            html, ghsa_id=_GHSA_ID, cve_id=_CVE_ID
        )

        self.assertEqual(versions, _FIXED)
        self.assertEqual(len(digest), 64)

    def test_rejects_github_advisory_with_mismatched_cve_identity(self) -> None:
        html = f"<p>{_GHSA_ID} CVE-2026-54321</p>"

        with self.assertRaisesRegex(ValueError, "identity"):
            parse_github_advisory(html, ghsa_id=_GHSA_ID, cve_id=_CVE_ID)

    @patch("patrick.definitions._fetch_github_advisory")
    @patch("patrick.definitions._fetch_nvd_cves")
    def test_adds_validated_core_rule_to_user_cache(
        self, fetch_nvd, fetch_github
    ) -> None:
        fetch_nvd.return_value = ([_record()], _source_metadata())
        fetch_github.return_value = {
            "fixed_versions": _FIXED,
            "sha256": "b" * 64,
            "checked_at": "2026-11-17T00:00:00+00:00",
        }
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "php-runtime-updated.json"
            _write_base_catalog(cache)

            report = refresh_php_definitions(cache_file=cache)

            rules = load_rules(cache)
            catalog = json.loads(cache.read_text(encoding="utf-8"))
            with patch(
                "patrick.scanner.definition_cache_path",
                return_value=cache,
            ):
                active_rules = load_rules()

        self.assertEqual(report["status"], "updated")
        self.assertEqual(report["rules_added"], 1)
        self.assertEqual(report["php_core_records"], 1)
        self.assertEqual(len(rules), 2)
        self.assertIn(_CVE_ID, {rule.id for rule in active_rules})
        added = next(rule for rule in rules if rule.id == _CVE_ID)
        self.assertEqual(added.fixed_versions["8.5"], (8, 5, 12))
        self.assertEqual(added.published_at, "2026-10-21T14:17:09.357")
        self.assertEqual(catalog["update_metadata"]["status"], "updated")

    @patch("patrick.definitions._fetch_github_advisory")
    @patch("patrick.definitions._fetch_nvd_cves")
    def test_selected_php_profile_is_recorded_without_dropping_other_branches(
        self, fetch_nvd, fetch_github
    ) -> None:
        fetch_nvd.return_value = ([_record()], _source_metadata())
        fetch_github.return_value = {
            "fixed_versions": _FIXED,
            "sha256": "b" * 64,
            "checked_at": "2026-11-17T00:00:00+00:00",
        }
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "php-runtime-updated.json"
            _write_base_catalog(cache)

            report = refresh_php_definitions(cache_file=cache, php_version="8.2")

            catalog = json.loads(cache.read_text(encoding="utf-8"))
            rules = load_rules(cache)

        self.assertEqual(report["php_version_profile"], "8.2")
        self.assertEqual(catalog["update_metadata"]["php_version_profile"], "8.2")
        self.assertIn("8.5", next(rule for rule in rules if rule.id == _CVE_ID).fixed_versions)

    def test_invalid_php_version_profile_is_rejected_before_fetching(self) -> None:
        with patch("patrick.definitions._fetch_nvd_cves") as fetch_nvd:
            with self.assertRaisesRegex(ValueError, "major.minor"):
                refresh_php_definitions(php_version="8.2.1")

        fetch_nvd.assert_not_called()

    @patch("patrick.catalog.definition_cache_path")
    def test_partial_cache_status_is_reported_to_scans(self, cache_path) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "php-runtime-updated.json"
            cache.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "rules": [],
                        "update_metadata": {
                            "status": "partial",
                            "checked_at": "2026-11-17T00:00:00+00:00",
                            "php_core_records": 2,
                            "php_extension_records": 4,
                            "out_of_scope_records": 102,
                            "php_version_profile": "8.2",
                            "issues": ["one advisory could not be validated"],
                        },
                    }
                ),
                encoding="utf-8",
            )
            cache_path.return_value = cache

            status = definition_update_status()

        self.assertEqual(status["status"], "partial")
        self.assertEqual(status["php_core_records"], 2)
        self.assertEqual(status["php_extension_records"], 4)
        self.assertEqual(status["out_of_scope_records"], 102)
        self.assertEqual(status["php_version_profile"], "8.2")
        self.assertEqual(
            status["issues"], ["one advisory could not be validated"]
        )

    @patch("patrick.definitions._fetch_github_advisory")
    @patch("patrick.definitions._fetch_nvd_cves")
    def test_conflicting_upstream_ranges_are_not_applied(
        self, fetch_nvd, fetch_github
    ) -> None:
        fetch_nvd.return_value = ([_record()], _source_metadata())
        fetch_github.return_value = {
            "fixed_versions": {"8.5": "8.5.13"},
            "sha256": "b" * 64,
            "checked_at": "2026-11-17T00:00:00+00:00",
        }
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "php-runtime-updated.json"
            _write_base_catalog(cache)

            report = refresh_php_definitions(cache_file=cache)

            rules = load_rules(cache)

        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["rules_added"], 0)
        self.assertIn("conflicting", report["issues"][0])
        self.assertNotIn(_CVE_ID, {rule.id for rule in rules})

    @patch("patrick.definitions._fetch_github_advisory")
    @patch("patrick.definitions._fetch_nvd_cves")
    def test_extension_advisory_is_added_to_extension_catalog(
        self, fetch_nvd, fetch_github
    ) -> None:
        record = _record()
        record["affected"][0]["affectedData"][0]["packageName"] = "ext-openssl"
        fetch_nvd.return_value = ([record], _source_metadata())
        fetch_github.return_value = {
            "fixed_versions": _FIXED,
            "sha256": "b" * 64,
            "checked_at": "2026-11-17T00:00:00+00:00",
        }
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "php-runtime-updated.json"
            _write_base_catalog(cache)
            report = refresh_php_definitions(cache_file=cache)
            extension_rule = next(
                rule for rule in load_rules(cache) if rule.id == _CVE_ID
            )

        self.assertEqual(report["status"], "updated")
        self.assertEqual(report["php_core_records"], 0)
        self.assertEqual(report["php_extension_records"], 1)
        self.assertEqual(report["out_of_scope_records"], 0)
        self.assertEqual(report["rules_added"], 1)
        self.assertEqual(extension_rule.component, "php-extension")
        self.assertEqual(extension_rule.package_name, "openssl")
        fetch_github.assert_called_once()

    @patch("patrick.definitions._fetch_github_advisory")
    @patch("patrick.definitions._fetch_nvd_cves")
    def test_extension_advisory_requires_a_named_supported_package(
        self, fetch_nvd, fetch_github
    ) -> None:
        record = _record()
        record["affected"][0]["affectedData"][0]["packageName"] = "PHP-FPM"
        fetch_nvd.return_value = ([record], _source_metadata())
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "php-runtime-updated.json"
            _write_base_catalog(cache)

            report = refresh_php_definitions(cache_file=cache)

        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["php_extension_records"], 0)
        self.assertEqual(report["out_of_scope_records"], 1)
        fetch_github.assert_not_called()

    @patch("patrick.definitions._fetch_github_advisory")
    @patch("patrick.definitions._fetch_nvd_cves")
    def test_extension_accepts_exact_first_release_branch_range(
        self, fetch_nvd, fetch_github
    ) -> None:
        record = _record()
        package = record["affected"][0]["affectedData"][0]
        package["packageName"] = "openssl"
        package["versions"][0]["version"] = "8.5.0"
        fetch_nvd.return_value = ([record], _source_metadata())
        fetch_github.return_value = {
            "fixed_versions": _FIXED,
            "sha256": "b" * 64,
            "checked_at": "2026-11-17T00:00:00+00:00",
        }
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "php-runtime-updated.json"
            _write_base_catalog(cache)

            report = refresh_php_definitions(cache_file=cache)

        self.assertEqual(report["status"], "updated")
        self.assertEqual(report["php_extension_records"], 1)

    @patch("patrick.definitions._fetch_github_advisory")
    @patch("patrick.definitions._fetch_nvd_cves")
    def test_updates_existing_definition_after_validated_amendment(
        self, fetch_nvd, fetch_github
    ) -> None:
        fetch_nvd.return_value = ([_record("8.5.12")], _source_metadata())
        fetch_github.return_value = {
            "fixed_versions": {"8.5": "8.5.12"},
            "sha256": "b" * 64,
            "checked_at": "2026-11-17T00:00:00+00:00",
        }
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "php-runtime-updated.json"
            _write_base_catalog(cache)
            initial = refresh_php_definitions(cache_file=cache)
            fetch_nvd.return_value = ([_record("8.5.13")], _source_metadata())
            fetch_github.return_value = {
                "fixed_versions": {"8.5": "8.5.13"},
                "sha256": "b" * 64,
                "checked_at": "2026-11-17T00:00:00+00:00",
            }
            amended = refresh_php_definitions(cache_file=cache)
            updated = next(
                rule for rule in load_rules(cache) if rule.id == _CVE_ID
            )

        self.assertEqual(initial["rules_added"], 1)
        self.assertEqual(amended["rules_updated"], 1)
        self.assertEqual(updated.fixed_versions["8.5"], (8, 5, 13))

    @patch("patrick.cli.refresh_mysql_definitions")
    @patch("patrick.cli.refresh_php_definitions")
    def test_definitions_mode_renders_json_update_report(
        self, refresh, refresh_mysql
    ) -> None:
        refresh.return_value = {
            "schema_version": 1,
            "feature": "PHP Vulnerability Definition Update",
            "mode": "php-vulnerability-definition-update",
            "status": "updated",
            "checked_at": "2026-11-17T00:00:00+00:00",
            "catalog_path": "/tmp/php-runtime-updated.json",
            "php_version_profile": "8.2",
            "nvd_records": 1,
            "php_cna_records": 1,
            "php_core_records": 1,
            "rules_added": 1,
            "rules_updated": 0,
            "rules_unchanged": 0,
            "out_of_scope_records": 0,
            "sources": [],
            "issues": [],
            "limitations": [],
        }
        refresh_mysql.return_value = {
            "status": "updated",
            "rules": 2,
            "issues": [],
            "source": {
                "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "sha256": "b" * 64,
                "checked_at": "2026-11-17T00:00:00+00:00",
            },
        }
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                [
                    "--mode",
                    "definitions",
                    "--php-version",
                    "8.2",
                    "--format",
                    "json",
                ]
            )

        self.assertEqual(exit_code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["feature"], "PHP Vulnerability Definition Update")
        self.assertEqual(report["php_version_profile"], "8.2")
        refresh.assert_called_once_with(php_version="8.2")
        refresh_mysql.assert_called_once_with()

    @patch("patrick.cli.definition_update_status")
    @patch("patrick.cli._get_release_data")
    def test_partial_definition_update_marks_normal_scan_incomplete(
        self, release_data, definition_status
    ) -> None:
        release_data.return_value = (
            {
                "8.5": {
                    "version": "8.5.12",
                    "date": "2026-10-21",
                    "supported": True,
                    "security_release": False,
                    "source_url": "https://www.php.net/",
                    "checked_at": "2026-11-17T00:00:00+00:00",
                }
            },
            {"status": "updated", "issues": []},
        )
        definition_status.return_value = {
            "status": "partial",
            "issues": ["one definition could not be validated"],
        }
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".php-version").write_text("8.5.12", encoding="utf-8")
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main([str(project)])

        self.assertEqual(exit_code, 3)
        self.assertIn("definition update status: partial", output.getvalue())
        self.assertIn("one definition could not be validated", output.getvalue())


if __name__ == "__main__":
    unittest.main()
