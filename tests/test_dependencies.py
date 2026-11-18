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
from patrick.dependencies import _query_osv, scan_dependencies
from patrick.mysql_advisories import (
    _rule,
    assess_mysql_version,
    load_mysql_definitions,
    refresh_mysql_definitions,
)
from patrick.mysql_runtime import inspect_mysql_server


def _nvd_mysql_record() -> dict:
    return {
        "id": "CVE-2026-12345",
        "vulnStatus": "Analyzed",
        "published": "2026-01-02T00:00:00.000",
        "lastModified": "2026-02-03T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "A test MySQL vulnerability."}],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "8.0.0",
                                "versionEndExcluding": "8.0.30",
                            }
                        ],
                    }
                ]
            }
        ],
        "references": [{"url": "https://example.test/advisory"}],
    }


class DependencyScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        cache = tempfile.TemporaryDirectory()
        self.addCleanup(cache.cleanup)
        patcher = patch.dict(os.environ, {"XDG_CACHE_HOME": cache.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _write_lock(self) -> None:
        (self.root / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {"name": "vendor/library", "version": "1.2.3"}
                    ],
                    "packages-dev": [
                        {"name": "vendor/test-tool", "version": "2.0.0"}
                    ],
                }
            ),
            encoding="utf-8",
        )

    @patch("patrick.dependencies._query_osv")
    def test_scans_locked_composer_dependencies(self, query) -> None:
        self._write_lock()
        query.return_value = (
            [
                [
                    {
                        "id": "GHSA-abcd-efgh-ijkl",
                        "summary": "A test package issue.",
                        "references": [{"url": "https://example.test/issue"}],
                    }
                ],
                [],
            ],
            512,
        )

        report = scan_dependencies(self.root)

        self.assertEqual(report["feature"], "MySQL & Third-Party Dependency Scan")
        self.assertEqual(report["status"], "potentially_affected")
        self.assertEqual(report["dependency_count"], 2)
        self.assertEqual(
            report["dependencies"][0]["status"], "potentially_affected"
        )
        self.assertEqual(report["dependencies"][1]["status"], "no_known_vulnerabilities")
        query.assert_called_once_with(
            [("vendor/library", "1.2.3"), ("vendor/test-tool", "2.0.0")],
            response_budget=16 * 1024 * 1024,
        )

    @patch("patrick.dependencies._query_osv")
    def test_offline_scan_does_not_query_osv_and_reports_unknown(self, query) -> None:
        self._write_lock()

        report = scan_dependencies(self.root, offline=True)

        query.assert_not_called()
        self.assertEqual(report["status"], "unknown")
        self.assertTrue(
            all(item["status"] == "unknown" for item in report["dependencies"])
        )

    def test_missing_lock_file_is_unknown_not_clean(self) -> None:
        report = scan_dependencies(self.root, offline=True)

        self.assertEqual(report["status"], "unknown")
        self.assertEqual(report["dependency_count"], 0)
        self.assertTrue(any("No composer.lock" in issue for issue in report["issues"]))

    @patch("patrick.dependencies._query_osv")
    @patch("patrick.dependencies.inspect_mysql_server")
    @patch("patrick.dependencies.load_mysql_definitions")
    def test_checks_selected_mysql_binary_against_local_nvd_ranges(
        self, load_catalog, inspect, query
    ) -> None:
        self._write_lock()
        query.return_value = ([[], []], 128)
        inspect.return_value = {
            "binary": "/tmp/mysqld",
            "product": "Oracle MySQL",
            "version": "8.0.29",
            "limitations": [],
        }
        rule = _rule(_nvd_mysql_record())
        load_catalog.return_value = {
            "status": "updated",
            "checked_at": "2026-02-04T00:00:00+00:00",
            "rules": [rule],
            "issues": [],
            "source": {"url": "https://services.nvd.nist.gov/"},
        }

        report = scan_dependencies(self.root, mysql_binary=Path("/tmp/mysqld"))

        self.assertEqual(report["mysql"]["status"], "potentially_affected")
        self.assertEqual(report["mysql"]["findings"][0]["id"], "CVE-2026-12345")
        self.assertEqual(report["status"], "potentially_affected")

    def test_mysql_range_parser_rejects_conditional_platform_rules(self) -> None:
        record = _nvd_mysql_record()
        record["configurations"][0]["nodes"][0]["operator"] = "AND"
        record["configurations"][0]["nodes"][0]["cpeMatch"].append(
            {
                "vulnerable": False,
                "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
            }
        )

        with self.assertRaisesRegex(ValueError, "cannot be assessed safely"):
            _rule(record)

    def test_mysql_range_parser_rejects_multiple_anded_mysql_ranges(self) -> None:
        record = _nvd_mysql_record()
        record["configurations"][0]["nodes"][0]["operator"] = "AND"
        record["configurations"][0]["nodes"][0]["cpeMatch"].append(
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "8.0.0",
                "versionEndExcluding": "8.0.30",
            }
        )

        with self.assertRaisesRegex(ValueError, "cannot be assessed safely"):
            _rule(record)

    def test_mysql_version_assessment_obeys_inclusive_and_exclusive_bounds(self) -> None:
        rule = _rule(_nvd_mysql_record())
        catalog = {
            "status": "updated",
            "rules": [rule],
            "checked_at": "2026-02-04T00:00:00+00:00",
            "issues": [],
        }

        affected = assess_mysql_version("8.0.29", catalog)
        fixed = assess_mysql_version("8.0.30", catalog)

        self.assertEqual(affected["status"], "potentially_affected")
        self.assertEqual(fixed["status"], "no_known_vulnerabilities")

    @patch("patrick.mysql_advisories._fetch_nvd_cves_for_cpe")
    def test_explicit_mysql_definition_refresh_writes_local_catalog(self, fetch) -> None:
        fetch.return_value = (
            [_nvd_mysql_record()],
            {
                "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "sha256": "a" * 64,
                "records": 1,
                "checked_at": "2026-02-04T00:00:00+00:00",
            },
        )
        cache = self.root / "mysql-advisories.json"

        report = refresh_mysql_definitions(cache_file=cache)
        catalog = load_mysql_definitions(cache)

        self.assertEqual(report["status"], "updated")
        self.assertEqual(report["rules"], 1)
        self.assertEqual(catalog["rules"][0]["id"], "CVE-2026-12345")
        fetch.assert_called_once()

    def test_osv_request_contains_only_package_identity_and_version(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def geturl(self):
                return "https://api.osv.dev/v1/querybatch"

            def read(self, _limit):
                return b'{"results":[{"vulns":[]}]}'

        class FakeOpener:
            def open(self, request, timeout):
                self.request = request
                self.timeout = timeout
                return FakeResponse()

        opener = FakeOpener()
        with patch(
            "patrick.dependencies.build_opener",
            return_value=opener,
        ):
            results, _response_bytes = _query_osv(
                [("vendor/library", "1.2.3")]
            )

        request = opener.request
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(results, [[]])
        self.assertEqual(
            payload,
            {
                "queries": [
                    {
                        "package": {
                            "name": "vendor/library",
                            "ecosystem": "Packagist",
                        },
                        "version": "1.2.3",
                    }
                ]
            },
        )
        self.assertNotIn(str(self.root), request.data.decode("utf-8"))

    def test_inspects_only_selected_server_version_without_shell(self) -> None:
        binary = self.root / "mysqld"
        binary.touch()
        binary.chmod(0o755)
        with patch(
            "patrick.mysql_runtime.subprocess.run",
            return_value=subprocess.CompletedProcess(
                [str(binary), "--version"],
                0,
                stdout="mysqld Ver 8.0.29 for macos14.0 on arm64\n",
                stderr="",
            ),
        ) as run:
            result = inspect_mysql_server(binary)

        self.assertEqual(result["product"], "Oracle MySQL")
        self.assertEqual(result["version"], "8.0.29")
        run.assert_called_once()
        self.assertNotIn("shell", run.call_args.kwargs)

    @patch("patrick.cli.scan_dependencies")
    def test_dependencies_mode_emits_feature_report_and_exit_code(self, scan) -> None:
        scan.return_value = {
            "feature": "MySQL & Third-Party Dependency Scan",
            "mode": "mysql-third-party-dependency-scan",
            "status": "unknown",
            "dependency_count": 0,
            "dependencies": [],
            "osv": {"status": "skipped"},
            "mysql": {"status": "not_selected", "findings": []},
            "issues": ["No composer.lock was found."],
            "limitations": [],
        }
        output = StringIO()

        with redirect_stdout(output):
            exit_code = main(
                ["--mode", "dependencies", str(self.root), "--offline", "--format", "json"]
            )

        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 3)
        self.assertEqual(report["feature"], "MySQL & Third-Party Dependency Scan")
        scan.assert_called_once()


if __name__ == "__main__":
    unittest.main()
