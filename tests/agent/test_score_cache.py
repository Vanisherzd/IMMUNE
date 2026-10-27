import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import score  # noqa: E402


class ScoreCacheTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = pathlib.Path(self.temp_dir.name)
        self.drill_log = root / "drills-20261022-test.log"
        self.shim_log = root / "oai-shim.log"
        self.drill_log.write_text(
            "=== 10:00:00 reset + inject bad-config\n"
            "verify: / 200 /api/ 200 -> PASS\n"
            "injected bad-config: / 0 /api/ 0\n"
            "=== 10:00:05 NemoClaw agent turn\n"
            "Root cause: nginx config syntax error. Final health: both return 200.\n"
            "=== 10:01:05 verify\n"
            "verify: / 200 /api/ 200 -> PASS\n"
            "=== ops-api.log (what the sandbox agent called)\n"
            "10:00:10 1.2.3.4 docker_logs {} -> syntax error\n"
            "DRILL_DONE 10:01:05\n"
        )

    def timestamp(self, clock):
        return time.mktime(time.strptime(f"20261022 {clock}", "%Y%m%d %H:%M:%S"))

    def write_shim(self, usage_rows):
        self.shim_log.write_text("".join(
            json.dumps({"ts": self.timestamp(clock), "usage": usage}) + "\n"
            for clock, usage in usage_rows
        ))

    def test_cache_hit_is_aggregated_and_shown(self):
        self.write_shim([
            ("10:00:10", {"prompt_tokens": 100, "cached_tokens": 40, "completion_tokens": 10}),
            ("10:00:20", {"prompt_tokens": 300, "cached_tokens": 160, "completion_tokens": 20}),
            ("10:02:00", {"prompt_tokens": 500, "cached_tokens": 500, "completion_tokens": 30}),
        ])

        records = score.load([self.drill_log], self.shim_log)

        self.assertEqual(records[0]["prompt_tokens"], 400)
        self.assertEqual(records[0]["cached_tokens"], 200)
        self.assertEqual(records[0]["requests"], 2)
        self.assertEqual(records[0]["tokens"], 30)
        self.assertEqual(records[0]["cache_hit"], 0.5)
        self.assertIn("| cache |", score.scorecard(records))
        self.assertIn("; cache 50%", score.scorecard(records))
        table = score.cache_table(records, self.shim_log)
        self.assertEqual(table.count("2026-10-22 10:00:"), 2)
        self.assertNotIn("10:02:00", table)

    def test_missing_cached_tokens_preserves_scorecard_output(self):
        self.write_shim([
            ("10:00:10", {"prompt_tokens": 100, "completion_tokens": 10}),
        ])

        records = score.load([self.drill_log], self.shim_log)
        legacy_records = [dict(records[0])]
        for field in ("prompt_tokens", "cached_tokens", "requests", "cache_hit"):
            legacy_records[0].pop(field)

        self.assertIsNone(records[0]["cache_hit"])
        self.assertEqual(score.scorecard(records), score.scorecard(legacy_records))

    def test_cache_flag_prints_each_request_in_the_drill_window(self):
        self.write_shim([
            ("10:00:10", {"prompt_tokens": 100, "cached_tokens": 40, "completion_tokens": 10}),
            ("10:00:20", {"prompt_tokens": 300, "cached_tokens": 160, "completion_tokens": 20}),
            ("10:02:00", {"prompt_tokens": 500, "cached_tokens": 500, "completion_tokens": 30}),
        ])

        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "score.py"), str(self.drill_log),
             "--shim", str(self.shim_log), "--cache"],
            check=True, capture_output=True, text=True,
        )

        self.assertEqual(result.stdout.count("| timestamp | prompt_tokens |"), 1)
        self.assertEqual(result.stdout.count("2026-10-22 10:00:"), 2)
        self.assertNotIn("10:02:00", result.stdout)


if __name__ == "__main__":
    unittest.main()
