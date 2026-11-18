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
from patrick.scanner import load_source_rules, scan_source


class SourceScanTests(unittest.TestCase):
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

    def test_reports_php_call_with_path_line_and_column(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src" / "example.php"
            source.parent.mkdir()
            source.write_text("<?php\n$result = eval($input);\n", encoding="utf-8")

            report = scan_source(root, load_source_rules())

        self.assertEqual(report["feature"], "PHP Source Syntax Scan")
        self.assertEqual(report["mode"], "php-source-syntax-scan")
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["status"], "candidate")
        self.assertEqual(report["findings"][0]["evidence"]["path"], "src/example.php")
        self.assertEqual(report["findings"][0]["evidence"]["line"], 2)
        self.assertEqual(report["findings"][0]["evidence"]["column"], 11)
        self.assertEqual(
            report["findings"][0]["evidence"]["match_type"], "php-call-expression"
        )

    def test_custom_literal_matches_only_php_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.php").write_text(
                "<?php\n// risky_marker\n$text = 'risky_marker';\nrisky_marker();\n",
                encoding="utf-8",
            )
            rule = {**load_source_rules()[0], "pattern": "risky_marker"}

            report = scan_source(root, [rule])

        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["evidence"]["line"], 4)
        self.assertEqual(
            report["findings"][0]["evidence"]["match_type"], "php-code-literal"
        )

    def test_ignores_comments_strings_inline_html_and_non_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.php").write_text(
                """<div>system($html)</div>
<?php
// system($comment);
# eval($comment);
/* unserialize($comment); */
$text = 'shell_exec($string)';
$other = "system($string)";
function system($value) {}
$object->system($value);
Example::system($value);
new System($value);
echo 'safe';
""",
                encoding="utf-8",
            )

            report = scan_source(root, load_source_rules())

        self.assertEqual(report["findings"], [])

    def test_matches_multiline_and_namespaced_function_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.php").write_text(
                "<?php\n$result = \\App\\system\n    ($input);\n",
                encoding="utf-8",
            )

            report = scan_source(root, load_source_rules())

        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["rule_id"], "PHP-SOURCE-SYSTEM")
        self.assertEqual(report["findings"][0]["evidence"]["line"], 2)
        self.assertEqual(report["findings"][0]["evidence"]["column"], 11)

    def test_scans_mixed_php_and_html_after_multiple_open_tags(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "template.php").write_text(
                "<?php echo 'start'; ?>\n"
                "<div>system($html)</div>\n"
                "<?php eval($input);\n"
                "?>\n<footer>shell_exec($html)</footer>\n",
                encoding="utf-8",
            )

            report = scan_source(root, load_source_rules())

        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["rule_id"], "PHP-SOURCE-EVAL")
        self.assertEqual(report["findings"][0]["evidence"]["line"], 3)

    def test_ignores_heredoc_and_nowdoc_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.php").write_text(
                """<?php
$text = <<<TEXT
eval($not_a_call);
TEXT;
$literal = <<<'NOWDOC'
system($not_a_call);
NOWDOC;
""",
                encoding="utf-8",
            )

            report = scan_source(root, load_source_rules())

        self.assertEqual(report["findings"], [])

    def test_scans_after_heredoc_with_following_expression(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.php").write_text(
                "<?php\n$text = <<<TEXT\nignored\nTEXT . 'suffix';\nsystem($input);\n",
                encoding="utf-8",
            )

            report = scan_source(root, load_source_rules())

        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["rule_id"], "PHP-SOURCE-SYSTEM")
        self.assertEqual(report["findings"][0]["evidence"]["line"], 5)

    def test_text_output_reports_columns_and_scan_limitations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.php").write_text(
                "<?php\neval($input);\n", encoding="utf-8"
            )
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(
                    ["--mode", "source", str(root), "--skip-environment-check"]
                )

        self.assertIn("app.php:2:1", output.getvalue())
        self.assertIn("not a full PHP parser", output.getvalue())
        self.assertEqual(exit_code, 1)

    def test_source_mode_is_labeled_and_case_insensitive_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.php").write_text("<?php EVAL($input);\n", encoding="utf-8")
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(
                    [
                        "--mode",
                        "source",
                        str(root),
                        "--skip-environment-check",
                        "--format",
                        "json",
                    ]
                )

        report = json.loads(output.getvalue())
        self.assertEqual(report["feature"], "PHP Source Syntax Scan")
        self.assertEqual(report["environment_check"]["status"], "skipped")
        self.assertEqual(report["findings"][0]["rule_id"], "PHP-SOURCE-EVAL")
        self.assertEqual(exit_code, 1)

    @patch("patrick.cli.scan_source")
    @patch("patrick.cli.refresh_php_releases")
    @patch("patrick.cli.scan_local_environment")
    @patch("patrick.cli.default_php_executable")
    def test_source_scan_preflights_default_php_before_source(
        self, find_php, inspect_php, refresh, run_source
    ) -> None:
        events: list[str] = []
        find_php.return_value = Path("/usr/bin/php")

        def inspect(_binary):
            events.append("environment")
            return {
                "feature": "Local PHP Runtime Scan",
                "runtime": {
                    "binary": "/usr/bin/php",
                    "version": "8.5.12",
                    "modules": ["json", "pdo_mysql"],
                    "loaded_configuration": "/etc/php.ini",
                    "additional_ini_directory": "/etc/php/conf.d",
                    "limitations": [],
                },
                "issues": [],
            }

        def scan_source_after_preflight(_root, _source_rules):
            events.append("source")
            return {
                "schema_version": 1,
                "feature": "PHP Source Syntax Scan",
                "mode": "php-source-syntax-scan",
                "target": "/project",
                "files_scanned": 1,
                "rules_loaded": 4,
                "findings": [],
                "issues": [],
                "limitations": [],
            }

        inspect_php.side_effect = inspect
        refresh.return_value = (
            {
                "8.5": {
                    "version": "8.5.12",
                    "date": "16 Nov 2026",
                    "supported": True,
                    "security_release": True,
                    "source_url": "https://www.php.net/releases/index.php?json&version=8.5",
                    "checked_at": "2026-11-16T00:00:00+00:00",
                }
            },
            {"status": "updated", "source": "PHP.net", "issues": []},
        )
        run_source.side_effect = scan_source_after_preflight
        output = StringIO()
        with tempfile.TemporaryDirectory() as directory:
            with redirect_stdout(output):
                exit_code = main(
                    ["--mode", "source", directory, "--format", "json"]
                )

        report = json.loads(output.getvalue())
        self.assertEqual(events, ["environment", "source"])
        self.assertEqual(report["environment_check"]["status"], "checked")
        self.assertEqual(
            report["environment_check"]["assessment"], "unknown"
        )
        self.assertEqual(
            report["environment_check"]["runtime"]["version"], "8.5.12"
        )
        self.assertEqual(exit_code, 3)

    @patch("patrick.cli.scan_local_environment")
    def test_skip_environment_check_does_not_inspect_php(self, inspect_php) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = StringIO()
            with redirect_stdout(output):
                main(
                    [
                        "--mode",
                        "source",
                        directory,
                        "--skip-environment-check",
                        "--format",
                        "json",
                    ]
                )

        inspect_php.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["environment_check"]["status"], "skipped")

    @patch("patrick.cli.scan_source")
    @patch("patrick.cli.default_php_executable", return_value=None)
    def test_missing_php_still_runs_source_scan_and_reports_unknown(
        self, _find_php, run_source
    ) -> None:
        run_source.return_value = {
            "schema_version": 1,
            "feature": "PHP Source Syntax Scan",
            "mode": "php-source-syntax-scan",
            "target": "/project",
            "files_scanned": 4,
            "rules_loaded": 4,
            "findings": [],
            "issues": [],
            "limitations": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main(["--mode", "source", directory, "--format", "json"])

        report = json.loads(output.getvalue())
        self.assertEqual(report["environment_check"]["status"], "unavailable")
        self.assertEqual(report["files_scanned"], 4)
        run_source.assert_called_once()
        self.assertEqual(exit_code, 3)

    @patch("patrick.cli.scan_source")
    @patch("patrick.cli.refresh_php_releases")
    @patch("patrick.cli.scan_local_environment")
    @patch(
        "patrick.cli.default_php_executable",
        return_value=Path("/usr/bin/php"),
    )
    def test_potentially_affected_environment_is_reported_but_source_runs(
        self, _find_php, inspect_php, refresh, run_source
    ) -> None:
        inspect_php.return_value = {
            "feature": "Local PHP Runtime Scan",
            "runtime": {
                "binary": "/usr/bin/php",
                "version": "8.5.11",
                "modules": [],
                "limitations": [],
            },
            "issues": [],
        }
        refresh.return_value = (
            {
                "8.5": {
                    "version": "8.5.12",
                    "date": "16 Nov 2026",
                    "supported": True,
                    "security_release": True,
                    "source_url": "https://www.php.net/releases/index.php?json&version=8.5",
                    "checked_at": "2026-11-16T00:00:00+00:00",
                }
            },
            {"status": "updated", "source": "PHP.net", "issues": []},
        )
        run_source.return_value = {
            "schema_version": 1,
            "feature": "PHP Source Syntax Scan",
            "mode": "php-source-syntax-scan",
            "target": "/project",
            "files_scanned": 4,
            "rules_loaded": 4,
            "findings": [],
            "issues": [],
            "limitations": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main(["--mode", "source", directory, "--format", "json"])

        report = json.loads(output.getvalue())
        self.assertEqual(
            report["environment_check"]["assessment"], "potentially_affected"
        )
        run_source.assert_called_once()
        self.assertEqual(exit_code, 1)

    def test_excludes_dependency_directories_and_non_php_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "vendor").mkdir()
            (root / "vendor" / "dependency.php").write_text(
                "eval($input);", encoding="utf-8"
            )
            (root / "venv").mkdir()
            (root / "venv" / "generated.php").write_text(
                "eval($input);", encoding="utf-8"
            )
            (root / "readme.txt").write_text("eval($input);", encoding="utf-8")
            (root / "clean.php").write_text("echo 'safe';", encoding="utf-8")

            report = scan_source(root, load_source_rules())

        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["findings"], [])

    def test_rejects_malformed_source_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            catalog = Path(directory) / "rules.json"
            catalog.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "rules": [
                            {
                                "id": "bad",
                                "title": "Bad",
                                "severity": [],
                                "summary": "Invalid severity",
                                "pattern": "eval(",
                                "references": [],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                load_source_rules(catalog)


if __name__ == "__main__":
    unittest.main()
