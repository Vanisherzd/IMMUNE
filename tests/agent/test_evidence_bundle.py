import importlib.util
import os
import pathlib
import sys
import time
import types
import unittest
from unittest.mock import Mock, patch

SCRIPTS = pathlib.Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))


def load_script(name):
    spec = importlib.util.spec_from_file_location(f"evidence_bundle_{name}_under_test", SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sdk = types.ModuleType("openai")
sdk.OpenAI = Mock(side_effect=AssertionError("LLM calls are forbidden in evidence-bundle tests"))
with patch.dict(sys.modules, {"openai": sdk}):
    agent = load_script("agent")
faults = load_script("faults")


class EvidenceBundleTest(unittest.TestCase):
    def setUp(self):
        health = patch.object(agent, "with_health", side_effect=lambda result: result + "\nhealth now: canned")
        health.start()
        self.addCleanup(health.stop)

    @staticmethod
    def fake_dispatch(tool, args, dry_run):
        time.sleep(0.3)
        return f"{tool} result"

    def test_gathers_first_look_in_parallel_and_keeps_fixed_order(self):
        started = time.monotonic()
        with patch.object(agent, "_run_tool", side_effect=self.fake_dispatch):
            result = agent.evidence_bundle({}, False)
        elapsed = time.monotonic() - started

        headings = [
            "## check_health {}",
            "## docker_ps {}",
            '## docker_logs {"name": "edge-victim", "tail": 30}',
            '## docker_logs {"name": "edge-victim-app", "tail": 30}',
            "## read_config {}",
            '## port_check {"port": 8880}',
            "## disk_usage {}",
        ]
        positions = [result.index(heading) for heading in headings]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(elapsed, 1.0)
        self.assertTrue(result.endswith("health now: canned"))

    def test_subcall_exception_is_reported_without_hiding_other_sections(self):
        def fail_one(tool, args, dry_run):
            if tool == "read_config":
                raise OSError("unreadable")
            return f"{tool} result"

        with patch.object(agent, "_run_tool", side_effect=fail_one):
            result = agent.evidence_bundle({}, False)

        self.assertIn("(evidence_bundle: read_config failed: OSError: unreadable)", result)
        self.assertIn("## disk_usage {}\ndisk_usage result", result)

    def test_subcall_timeout_returns_without_waiting_for_slow_item(self):
        def slow_disk(tool, args, dry_run):
            if tool == "disk_usage":
                time.sleep(1)
            return f"{tool} result"

        started = time.monotonic()
        with patch.object(agent, "EVIDENCE_BUNDLE_TIMEOUT", 0.2), \
                patch.object(agent, "_run_tool", side_effect=slow_disk):
            result = agent.evidence_bundle({}, False)
        elapsed = time.monotonic() - started

        self.assertIn("(evidence_bundle: disk_usage failed: timeout after 0.2s)", result)
        self.assertIn("## check_health {}\ncheck_health result", result)
        self.assertLess(elapsed, 0.5)

    def test_policy_and_ops_api_expose_read_only_bundle(self):
        with patch.dict(os.environ, {"HEALTHY_GUARD": "0"}), patch.dict(sys.modules, {"agent": agent}):
            ops_api = load_script("ops_api")

        self.assertIn("evidence_bundle", faults.DIAGNOSTIC)
        self.assertIn("evidence_bundle", {tool["name"] for tool in ops_api.TOOLS})
        self.assertNotIn("evidence_bundle", agent.MUTATING)


if __name__ == "__main__":
    unittest.main()
