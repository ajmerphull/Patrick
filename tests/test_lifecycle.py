from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from patrick.lifecycle import (
    _parse_response,
    _save_cache,
    refresh_php_lifecycle,
)


def _cycle(
    cycle: str = "8.5",
    *,
    support: str | bool = "2027-12-31",
    eol: str | bool = "2029-12-31",
) -> dict[str, object]:
    return {
        "cycle": cycle,
        "releaseDate": "2025-11-20",
        "eol": eol,
        "latest": f"{cycle}.12",
        "latestReleaseDate": "2026-10-21",
        "lts": False,
        "support": support,
    }


class PhpLifecycleTests(unittest.TestCase):
    def test_parses_valid_php_lifecycle_catalog(self) -> None:
        cycles = _parse_response(json.dumps([_cycle()]).encode())

        self.assertEqual(cycles["8.5"]["support_date"], "2027-12-31")
        self.assertEqual(cycles["8.5"]["eol_date"], "2029-12-31")
        self.assertEqual(cycles["8.5"]["latest_version"], "8.5.12")
        self.assertEqual(cycles["8.5"]["source_url"], "https://endoflife.date/api/php.json")

    def test_rejects_duplicate_or_malformed_cycles(self) -> None:
        with self.assertRaisesRegex(ValueError, "repeats cycle"):
            _parse_response(json.dumps([_cycle(), _cycle()]).encode())

        invalid = _cycle()
        invalid["support"] = "not-a-date"
        with self.assertRaisesRegex(ValueError, "lifecycle date"):
            _parse_response(json.dumps([invalid]).encode())

    def test_refreshes_and_caches_lifecycle_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache" / "lifecycle.json"
            cycle = {
                **_parse_response(json.dumps([_cycle()]).encode())["8.5"],
            }
            with patch(
                "patrick.lifecycle._fetch_cycles",
                return_value={"8.5": cycle},
            ):
                cycles, check = refresh_php_lifecycle({"8.5"}, cache_file=cache)

            self.assertEqual(cycles["8.5"]["cycle"], "8.5")
            self.assertEqual(check["status"], "updated")
            self.assertTrue(cache.is_file())

            with patch(
                "patrick.lifecycle._fetch_cycles",
                side_effect=ValueError("temporary network failure"),
            ):
                cached, failed_check = refresh_php_lifecycle(
                    {"8.5"}, cache_file=cache
                )

        self.assertEqual(cached["8.5"]["eol_date"], "2029-12-31")
        self.assertEqual(failed_check["status"], "cached")
        self.assertTrue(failed_check["issues"])

    def test_offline_uses_cache_and_reports_missing_branches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "lifecycle.json"
            cycle = _parse_response(json.dumps([_cycle()]).encode())["8.5"]
            _save_cache(cache, {"8.5": cycle})
            with patch("patrick.lifecycle._fetch_cycles") as fetch:
                cached, check = refresh_php_lifecycle(
                    {"8.5", "9.0"}, offline=True, cache_file=cache
                )

        fetch.assert_not_called()
        self.assertEqual(cached.keys(), {"8.5"})
        self.assertEqual(check["status"], "partial")
        self.assertTrue(any("9.0" in issue for issue in check["issues"]))

    def test_offline_without_cache_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cycles, check = refresh_php_lifecycle(
                {"8.5"}, offline=True, cache_file=Path(directory) / "none.json"
            )

        self.assertEqual(cycles, {})
        self.assertEqual(check["status"], "unavailable")
        self.assertTrue(check["issues"])


if __name__ == "__main__":
    unittest.main()
