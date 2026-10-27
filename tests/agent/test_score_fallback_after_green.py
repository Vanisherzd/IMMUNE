"""A self_heal after the stack is already healthy is not a fallback; one before the repair is. Calls after resolution are counted."""
import pathlib
import sys
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import score  # noqa: E402

HEAD = """=== 10:27:00 reset + inject upstream-down
injected upstream-down: / 200 /api/ 502
=== 10:27:05 NemoClaw agent turn
Root cause: upstream stopped
Actions: started it
Final health: both 200
=== 10:28:40 verify
verify: / 200 /api/ 200 -> PASS
=== ops-api.log (what the sandbox agent called)
"""
AFTER = HEAD + """10:27:30 172.19.0.2 docker_logs {"name": "edge-victim-app"} -> [logs] Exited (0)
10:27:39 172.19.0.2 docker_start {"name": "edge-victim-app"} -> edge-victim-app started health now: {"front": 200, "api": 200} -> both URLs healthy. The incident is resolved: report root cause, actions, final health and stop.
10:28:30 172.19.0.2 self_heal {"note": "runtime event continuation"} -> {"front": 200, "api": 200}
10:28:38 172.19.0.2 disk_usage {} -> scratch volume 0%
DRILL_DONE 10:28:41
"""
BEFORE = HEAD + """10:27:30 172.19.0.2 docker_logs {"name": "edge-victim-app"} -> [logs] Exited (0)
10:27:39 172.19.0.2 self_heal {"note": "cannot figure it out"} -> step log ... health now: {"front": 200, "api": 200} -> both URLs healthy. The incident is resolved
DRILL_DONE 10:28:41
"""


class FallbackAfterGreenTest(unittest.TestCase):
    def test_self_heal_after_resolution_is_autonomous_with_after_green_calls(self):
        r = score.score_block("upstream-down", "10:27:00", AFTER.split("\n", 1)[1])
        self.assertEqual(r["outcome"], "autonomous", r)
        self.assertEqual(r["after_green"], 2)

    def test_self_heal_before_resolution_is_a_fallback(self):
        r = score.score_block("upstream-down", "10:27:00", BEFORE.split("\n", 1)[1])
        self.assertEqual(r["outcome"], "fallback", r)


if __name__ == "__main__":
    unittest.main()
