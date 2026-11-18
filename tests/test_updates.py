from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from patrick.updates import refresh_php_releases


class ReleaseUpdateTests(unittest.TestCase):
    def test_refreshes_and_caches_official_release_facts(self) -> None:
        release = {
            "version": "8.5.12",
            "date": "21 Oct 2026",
            "supported": True,
            "security_release": True,
            "source_url": "https://www.php.net/releases/index.php?json&version=8.5",
            "checked_at": "2026-11-16T00:00:00+00:00",
        }
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache" / "releases.json"
            with patch("patrick.updates._fetch_branch", return_value=release):
                releases, check = refresh_php_releases({"8.5"}, cache_file=cache)

            self.assertEqual(releases, {"8.5": release})
            self.assertEqual(check["status"], "updated")
            self.assertTrue(cache.is_file())

            with patch(
                "patrick.updates._fetch_branch",
                side_effect=ValueError("temporary network failure"),
            ):
                cached, failed_check = refresh_php_releases({"8.5"}, cache_file=cache)

        self.assertEqual(cached, {"8.5": release})
        self.assertEqual(failed_check["status"], "cached")
        self.assertTrue(failed_check["issues"])

    def test_missing_remote_and_cached_data_is_reported_as_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "missing.json"
            with patch(
                "patrick.updates._fetch_branch",
                side_effect=ValueError("temporary network failure"),
            ):
                releases, check = refresh_php_releases({"8.5"}, cache_file=cache)

        self.assertEqual(releases, {})
        self.assertEqual(check["status"], "unavailable")
        self.assertTrue(check["issues"])


if __name__ == "__main__":
    unittest.main()
