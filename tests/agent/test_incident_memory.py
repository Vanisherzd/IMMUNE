import json
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
openai = types.ModuleType("openai")
openai.OpenAI = Mock
sys.modules.setdefault("openai", openai)
import agent
import incident_memory


class IncidentMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.temp.name) / "incident-memory.jsonl"
        self.env = patch.dict(os.environ, {"INCIDENT_MEMORY": "1", "INCIDENT_MEMORY_FILE": str(self.path)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def archive(self):
        return {
            "id": "incident-1", "ts": 1_700_000_000, "seconds": 12.5,
            "alert": "Alert: upstream requests fail with connection refused",
            "final_health": {"front": 200, "api": 200},
            "ops_api": [
                {"tool": "docker_logs", "args": {"name": "edge-victim-app"},
                 "result": "notice: starting\n[error] connect() failed: connection refused\n[error] later"},
                {"tool": "docker_restart", "args": {"name": "edge-victim-app"},
                 "result": "refused: read a runbook first"},
                {"tool": "docker_restart", "args": {"name": "edge-victim-app"}, "result": "restarted"},
                {"tool": "write_config", "args": {"content": "fixed"}, "result": "written"},
                {"tool": "check_health", "args": {}, "result": '{"front": 200, "api": 200}'},
            ],
            "reviews": [{"verdict": "REJECT"}],
            "agent_output": "tool noise\nRoot cause: the upstream config named a closed port. Final health is 200/200.",
        }

    def test_record_writes_verified_schema(self):
        incident = incident_memory.memory_from_archive(self.archive())

        written = incident_memory.record(incident)

        self.assertTrue(written)
        saved = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(set(saved), {"id", "ts", "symptoms", "containers", "actions", "diagnostics",
                                      "final_health", "seconds", "root_cause", "verification", "trust", "platform"})
        self.assertEqual(saved["verification"], {"health": "200/200", "reviewer_rejections": 1,
                                                  "policy_denials": 1})
        self.assertEqual(saved["trust"], "local_verified")

    def test_record_refuses_non_200_final_health(self):
        incident = incident_memory.memory_from_archive(self.archive())
        incident["final_health"]["api"] = 503

        written = incident_memory.record(incident)

        self.assertFalse(written)
        self.assertFalse(self.path.exists())

    def test_recall_finds_shared_symptom_and_renders_recovery(self):
        incident_memory.record(incident_memory.memory_from_archive(self.archive()))

        matches = incident_memory.recall("upstream connection refused")

        self.assertEqual(len(matches), 1)
        self.assertIn("this stack recovered from the same symptom", matches[0])
        self.assertIn('docker_restart {"name": "edge-victim-app"}; write_config {"content": "fixed"}', matches[0])
        self.assertIn("cause: Root cause: the upstream config named a closed port", matches[0])
        self.assertIn("verified 200/200", matches[0])

    def test_recall_returns_empty_when_file_is_missing(self):
        matches = incident_memory.recall("connection refused")

        self.assertEqual(matches, [])

    def test_recall_returns_empty_when_disabled(self):
        incident_memory.record(incident_memory.memory_from_archive(self.archive()))

        with patch.dict(os.environ, {"INCIDENT_MEMORY": "0"}):
            matches = incident_memory.recall("connection refused")

        self.assertEqual(matches, [])

    def test_memory_from_archive_keeps_only_executed_mutations_in_order(self):
        memory = incident_memory.memory_from_archive(self.archive())

        self.assertEqual(memory["actions"], [
            {"tool": "docker_restart", "args": {"name": "edge-victim-app"}},
            {"tool": "write_config", "args": {"content": "fixed"}},
        ])
        self.assertEqual(memory["diagnostics"], ["docker_logs", "check_health"])
        self.assertEqual(memory["symptoms"], ["Alert: upstream requests fail with connection refused",
                                               "[error] connect() failed: connection refused"])

    def test_agent_prepends_memory_without_changing_pack_verdict(self):
        kb = Mock()
        kb.retrieve.return_value = {"scenario": "other", "knowledge_match": {"status": "insufficient",
                                    "best_solution_coverage": 0.0}, "solutions": [],
                                    "weak_solution_candidates": [], "cases": []}
        with patch.object(agent, "knowledge_base", return_value=kb), \
             patch.object(incident_memory, "recall", return_value=["remembered recovery"]):
            result = agent.search_incident_knowledge("connection refused")

        self.assertTrue(result.startswith("## this stack's own verified recoveries\nremembered recovery\n\n"))
        self.assertIn("knowledge base (other): insufficient, best card coverage 0.00", result)


if __name__ == "__main__":
    unittest.main()
