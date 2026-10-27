"""Verified recoveries of this stack are recorded from drills and pushed next to the runbook on a close symptom match."""
import json
import os
import pathlib
import sys
import tempfile
import types
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
if "openai" not in sys.modules:
    try:
        import openai  # noqa: F401
    except Exception:
        sys.modules["openai"] = types.SimpleNamespace(OpenAI=object)
import agent  # noqa: E402
import incident_memory  # noqa: E402

LOG = [
    {"ts": "10:00:01", "from": "172.19.0.2", "tool": "docker_logs", "args": {"name": "edge-victim"},
     "result": '[logs of edge-victim]\n2026/10/22 02:00:00 [error] 30#30: *14 connect() failed (111: Connection refused) while connecting to upstream, client: 172.19.0.1'},
    {"ts": "10:00:02", "from": "tool-layer", "tool": "community_push", "args": {"query": "x"}, "result": "0 references"},
    {"ts": "10:00:05", "from": "172.19.0.2", "tool": "docker_start", "args": {"name": "edge-victim-app"}, "result": "edge-victim-app started\nhealth now: {...} -> both URLs healthy"},
]


class MemoryPushTest(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        os.environ["INCIDENT_MEMORY_FILE"] = str(self.tmp / "memory.jsonl")
        (self.tmp / "ops-api.log").write_text("\n".join(json.dumps(r) for r in LOG) + "\n")
        (self.tmp / "agent.out").write_text("Root cause: the upstream container edge-victim-app was stopped.\nActions: docker_start edge-victim-app\nFinal health: 200/200\n")
        incident_memory._cache_key = None

    def tearDown(self):
        os.environ.pop("INCIDENT_MEMORY_FILE", None)
        incident_memory._cache_key = None

    def test_record_drill_keeps_the_symptom_line_and_the_executed_action_only(self):
        self.assertTrue(incident_memory.record_drill("upstream-down", self.tmp / "ops-api.log", "", 21.0, self.tmp / "agent.out"))
        rec = json.loads((self.tmp / "memory.jsonl").read_text().splitlines()[0])
        self.assertEqual(rec["source"], "drill")
        self.assertEqual([a["tool"] for a in rec["actions"]], ["docker_start"])
        self.assertNotIn("community_push", rec["diagnostics"])
        self.assertTrue(any("Connection refused" in s for s in rec["symptoms"]))
        self.assertIn("upstream container", rec["root_cause"])

    def test_memory_note_pushes_on_a_close_match_and_stays_silent_otherwise(self):
        incident_memory.record_drill("upstream-down", self.tmp / "ops-api.log", "", 21.0, self.tmp / "agent.out")
        close = "2026/10/22 03:00:00 [error] 31#31: *2 connect() failed (111: Connection refused) while connecting to upstream, client: 172.19.0.1"
        note = agent.memory_note(close)
        self.assertIn("own verified recovery", note)
        self.assertIn("docker_start", note)
        self.assertEqual(agent.memory_note("[emerg] 1#1: unknown directive \"foo\" in /etc/nginx/conf.d/default.conf:3"), "")

    def test_disabled_by_env(self):
        incident_memory.record_drill("upstream-down", self.tmp / "ops-api.log", "", 21.0, self.tmp / "agent.out")
        os.environ["INCIDENT_MEMORY"] = "0"
        try:
            self.assertEqual(agent.memory_note("connect() failed (111: Connection refused) while connecting to upstream"), "")
        finally:
            os.environ.pop("INCIDENT_MEMORY", None)


if __name__ == "__main__":
    unittest.main()


class StatePathMemoryTest(MemoryPushTest):
    def test_container_state_line_recalls_with_two_shared_terms(self):
        incident_memory.record_drill("upstream-down", self.tmp / "ops-api.log", "", 21.0, self.tmp / "agent.out")
        note = agent.memory_note("edge-victim\tUp 3 seconds\nedge-victim-app\tExited (0) 5 seconds ago", min_shared=2)
        self.assertIn("own verified recovery", note)
