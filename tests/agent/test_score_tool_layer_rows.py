"""Rows the tool layer writes on its own (community_push) are shown in the drill log but never scored as agent calls."""
import pathlib
import sys
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import score  # noqa: E402

LOG = """=== 10:35:00 NemoClaw agent turn
10:35:10 172.19.0.2 docker_logs {"name": "edge-victim", "tail": 30} -> [logs of edge-victim] 2026/10/22 [error] upstream sent too big header
  [tool-layer] 10:35:11 community_push {"query": "upstream sent too big header"} -> 1 references
10:35:20 172.19.0.2 restore_config {"source": "known-good"} -> restored default.conf
health now: {"front": 200, "api": 200} -> both URLs healthy
DRILL_DONE 10:35:30
"""


class ToolLayerRowsTest(unittest.TestCase):
    def test_parse_calls_skips_tool_layer_rows(self):
        calls = score.parse_calls(LOG)
        self.assertEqual([c["tool"] for c in calls], ["docker_logs", "restore_config"])


if __name__ == "__main__":
    unittest.main()
