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
from patrick.definition_list import list_vulnerability_definitions


def _php_rule(
    rule_id: str,
    published_at: str | None,
    *,
    component: str = "php-core",
    package_name: str = "php-src",
) -> dict:
    rule = {
        "id": rule_id,
        "title": f"Advisory {rule_id}",
        "severity": "high",
        "component": component,
        "summary": f"Summary for {rule_id}.",
        "references": [f"https://nvd.nist.gov/vuln/detail/{rule_id}"],
        "fixed_versions": {"8.5": "8.5.12"},
        "package_name": package_name,
    }
    if published_at is not None:
        rule["published_at"] = published_at
    return rule


def _mysql_rule(rule_id: str, published_at: str) -> dict:
    return {
        "id": rule_id,
        "title": f"Advisory {rule_id}",
        "summary": f"Summary for {rule_id}.",
        "severity": "high",
        "published_at": published_at,
        "ranges": [{"versionEndExcluding": "8.0.40"}],
        "references": [f"https://nvd.nist.gov/vuln/detail/{rule_id}"],
    }


class VulnerabilityDefinitionListTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cache_root = Path(self.temp.name) / "cache"
        self.cache_root.mkdir()
        cache_environment = patch.dict(
            os.environ, {"XDG_CACHE_HOME": str(self.cache_root)}
        )
        cache_environment.start()
        self.addCleanup(cache_environment.stop)
        self.php_cache = (
            self.cache_root / "patrick" / "php-runtime-updated.json"
        )
        self.mysql_cache = (
            self.cache_root / "patrick" / "mysql-advisories.json"
        )

    def _write_php_catalog(
        self, rows: list[dict], php_version_profile: str | None = None
    ) -> None:
        self.php_cache.parent.mkdir(parents=True, exist_ok=True)
        metadata = {
            "status": "updated",
            "checked_at": "2026-11-17T00:00:00+00:00",
            "issues": [],
        }
        if php_version_profile is not None:
            metadata["php_version_profile"] = php_version_profile
        self.php_cache.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "rules": rows,
                    "update_metadata": metadata,
                }
            ),
            encoding="utf-8",
        )

    def _write_mysql_catalog(self, rows: list[dict]) -> None:
        self.mysql_cache.parent.mkdir(parents=True, exist_ok=True)
        self.mysql_cache.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "product": "Oracle MySQL Server",
                    "checked_at": "2026-11-17T00:00:00+00:00",
                    "source": {"url": "https://services.nvd.nist.gov/"},
                    "status": "updated",
                    "rules": rows,
                    "issues": [],
                }
            ),
            encoding="utf-8",
        )

    def test_lists_active_php_and_mysql_definitions_by_publication_date(self) -> None:
        self._write_php_catalog(
            [
                _php_rule("CVE-2026-10001", "2026-10-21T14:00:00"),
                _php_rule(
                    "CVE-2026-10002",
                    "2026-11-01T14:00:00",
                    component="php-extension",
                    package_name="openssl",
                ),
            ]
        )
        self._write_mysql_catalog(
            [_mysql_rule("CVE-2026-10003", "2026-10-31T14:00:00")]
        )

        report = list_vulnerability_definitions()

        self.assertEqual(report["status"], "complete")
        self.assertEqual(
            [row["id"] for row in report["definitions"]],
            ["CVE-2026-10002", "CVE-2026-10003", "CVE-2026-10001"],
        )
        self.assertEqual(
            report["definitions"][0]["component"], "php-extension"
        )
        self.assertEqual(
            report["definitions"][1]["component"], "mysql-server"
        )
        self.assertEqual(report["catalogs"]["php"]["status"], "updated")
        self.assertEqual(report["catalogs"]["mysql"]["status"], "updated")
        self.assertTrue(report["catalogs"]["mysql"]["included_in_profile"])
        self.assertEqual(
            report["catalogs"]["php"]["checked_at"],
            "2026-11-17T00:00:00+00:00",
        )

    def test_php_version_profile_filters_by_branch_and_excludes_mysql_rows(self) -> None:
        self._write_php_catalog(
            [
                _php_rule("CVE-2026-10020", "2026-11-01T14:00:00"),
                {
                    **_php_rule(
                        "CVE-2026-10021",
                        "2026-10-01T14:00:00",
                        component="php-extension",
                        package_name="openssl",
                    ),
                    "fixed_versions": {"8.2": "8.2.29"},
                },
                {
                    **_php_rule("CVE-2026-10022", "2026-09-01T14:00:00"),
                    "fixed_versions": {"8.2": "8.2.28"},
                },
                {
                    **_php_rule("CVE-2026-10028", "2026-08-01T14:00:00"),
                    "fixed_versions": {"8.2": "8.2.0"},
                },
            ],
            php_version_profile="8.2",
        )
        self._write_mysql_catalog(
            [_mysql_rule("CVE-2026-10023", "2026-11-02T14:00:00")]
        )

        report = list_vulnerability_definitions()

        self.assertEqual(report["php_version_profile"], "8.2")
        self.assertEqual(
            {row["id"] for row in report["definitions"]},
            {"CVE-2026-10021", "CVE-2026-10022"},
        )
        self.assertEqual(report["php_profile_counts"], {"php_core": 1, "php_extensions": 1})
        self.assertEqual(report["catalogs"]["php"]["php_version_profile"], "8.2")
        self.assertFalse(report["catalogs"]["mysql"]["included_in_profile"])
        self.assertEqual(report["status"], "complete")
        self.assertTrue(
            any("not all PHP extensions" in item for item in report["limitations"])
        )

    def test_explicit_all_profile_overrides_saved_branch_profile(self) -> None:
        self._write_php_catalog(
            [
                _php_rule("CVE-2026-10024", "2026-11-01T14:00:00"),
                {
                    **_php_rule("CVE-2026-10025", "2026-10-01T14:00:00"),
                    "fixed_versions": {"8.2": "8.2.29"},
                },
            ],
            php_version_profile="8.2",
        )
        self._write_mysql_catalog(
            [_mysql_rule("CVE-2026-10026", "2026-09-01T14:00:00")]
        )

        report = list_vulnerability_definitions(php_version="all")

        self.assertEqual(report["php_version_profile"], "all")
        self.assertEqual(
            {row["id"] for row in report["definitions"]},
            {"CVE-2026-10024", "CVE-2026-10025", "CVE-2026-10026"},
        )

    def test_branch_profile_without_core_rules_is_not_reported_as_clear(self) -> None:
        self._write_php_catalog(
            [_php_rule("CVE-2026-10027", "2026-11-01T14:00:00")],
            php_version_profile="8.2",
        )

        report = list_vulnerability_definitions()

        self.assertEqual(report["status"], "partial")
        self.assertTrue(
            any("not evidence that the branch has no vulnerabilities" in issue
                for issue in report["issues"])
        )

    def test_empty_updated_mysql_catalog_is_reported_as_unknown(self) -> None:
        self._write_php_catalog(
            [_php_rule("CVE-2026-10008", "2026-11-01T14:00:00")]
        )
        self._write_mysql_catalog([])

        report = list_vulnerability_definitions()

        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["catalogs"]["mysql"]["status"], "unknown")
        self.assertTrue(
            any("contains no definitions" in issue for issue in report["issues"])
        )

    def test_missing_mysql_metadata_is_explicit(self) -> None:
        mysql_rule = _mysql_rule("CVE-2026-10012", "2026-10-01T00:00:00")
        mysql_rule.pop("title")
        mysql_rule.pop("references")
        self._write_php_catalog(
            [_php_rule("CVE-2026-10013", "2026-11-01T14:00:00")]
        )
        self._write_mysql_catalog([mysql_rule])

        report = list_vulnerability_definitions()
        mysql_definition = next(
            row for row in report["definitions"] if row["id"] == "CVE-2026-10012"
        )

        self.assertEqual(report["status"], "partial")
        self.assertIsNone(mysql_definition["title"])
        self.assertEqual(mysql_definition["title_status"], "missing")
        self.assertEqual(mysql_definition["references_status"], "missing")

    def test_missing_publication_date_is_kept_and_reported_at_end(self) -> None:
        self._write_php_catalog(
            [
                _php_rule("CVE-2026-10004", None),
                _php_rule("CVE-2026-10005", "2026-11-01T14:00:00"),
                _php_rule("CVE-2026-10011", "not-a-date"),
            ]
        )
        self._write_mysql_catalog(
            [_mysql_rule("CVE-2026-10009", "2026-10-01T00:00:00")]
        )

        report = list_vulnerability_definitions()
        undated = report["definitions"][-2:]
        missing_date = next(row for row in undated if row["id"] == "CVE-2026-10004")
        invalid_date = next(row for row in undated if row["id"] == "CVE-2026-10011")

        self.assertEqual(report["status"], "partial")
        self.assertIsNone(missing_date["published_at"])
        self.assertEqual(missing_date["publication_date_status"], "missing")
        self.assertTrue(
            any("missing publication date" in issue for issue in report["issues"])
        )
        self.assertEqual(invalid_date["publication_date_status"], "invalid")
        self.assertTrue(
            any("invalid publication date" in issue for issue in report["issues"])
        )

    def test_bundled_php_rules_are_labeled_and_missing_mysql_is_not_hidden(self) -> None:
        report = list_vulnerability_definitions()

        self.assertEqual(report["catalogs"]["php"]["status"], "bundled")
        self.assertEqual(report["catalogs"]["mysql"]["status"], "unavailable")
        self.assertEqual(
            {row["id"] for row in report["definitions"]},
            {"CVE-2026-109618", "CVE-2026-109619"},
        )
        self.assertEqual(report["status"], "partial")

    def test_cli_json_reports_status_and_does_not_treat_list_as_a_finding(self) -> None:
        self._write_php_catalog(
            [_php_rule("CVE-2026-10006", "2026-11-01T14:00:00")]
        )
        self._write_mysql_catalog(
            [_mysql_rule("CVE-2026-10010", "2026-10-01T00:00:00")]
        )
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(["--mode", "list-definitions", "--format", "json"])

        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["feature"], "Vulnerability Definition List")
        self.assertEqual(report["definitions"][0]["id"], "CVE-2026-10006")

    def test_cli_branch_profile_is_visible_in_text_and_filters_definitions(self) -> None:
        self._write_php_catalog(
            [
                _php_rule("CVE-2026-10030", "2026-11-01T14:00:00"),
                {
                    **_php_rule("CVE-2026-10031", "2026-10-01T14:00:00"),
                    "fixed_versions": {"8.2": "8.2.29"},
                },
            ]
        )
        output = StringIO()

        exit_code = main(
            ["--mode", "list-definitions", "--php-version", "8.2"],
            stdout=output,
            stderr=StringIO(),
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("PHP definition-list profile: PHP 8.2", output.getvalue())
        self.assertIn("CVE-2026-10031", output.getvalue())
        self.assertNotIn("CVE-2026-10030", output.getvalue())

    def test_cli_rejects_malformed_php_branch_profile(self) -> None:
        error = StringIO()

        exit_code = main(
            ["--mode", "list-definitions", "--php-version", "8.2.1"],
            stdout=StringIO(),
            stderr=error,
        )

        self.assertEqual(exit_code, 2)
        self.assertIn("major.minor", error.getvalue())

    def test_custom_php_catalog_is_used_for_the_listing(self) -> None:
        custom = Path(self.temp.name) / "custom.json"
        custom.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "rules": [
                        _php_rule("CVE-2026-10007", "2026-11-01T14:00:00")
                    ],
                }
            ),
            encoding="utf-8",
        )
        self._write_mysql_catalog([])

        report = list_vulnerability_definitions(custom)

        self.assertEqual(report["catalogs"]["php"]["status"], "custom")
        self.assertEqual(
            [row["id"] for row in report["definitions"]],
            ["CVE-2026-10007"],
        )


if __name__ == "__main__":
    unittest.main()
